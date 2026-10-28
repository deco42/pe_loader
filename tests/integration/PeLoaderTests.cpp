#include "pe_loader/PeLoader.hpp"
#include "ModuleApi.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::atomic<int> g_destructorCalls{};

extern "C" void destructionObserved() { ++g_destructorCalls; }

void require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

std::vector<std::byte> readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot open fixture DLL: " + path.string());
    std::vector<char> raw{std::istreambuf_iterator<char>(stream), {}};
    std::vector<std::byte> bytes(raw.size());
    std::memcpy(bytes.data(), raw.data(), raw.size());
    return bytes;
}

struct NativeModule {
    explicit NativeModule(const std::filesystem::path& path) : handle(::LoadLibraryW(path.c_str())) {
        if (handle == nullptr) throw std::runtime_error("LoadLibraryW failed: " + std::to_string(::GetLastError()));
    }
    ~NativeModule() {
        if (handle != nullptr) ::FreeLibrary(handle);
    }
    NativeModule(const NativeModule&) = delete;
    NativeModule& operator=(const NativeModule&) = delete;

    template <typename T>
    T get(const char* name) const {
        auto address = ::GetProcAddress(handle, name);
        if (address == nullptr) throw std::runtime_error("GetProcAddress failed for " + std::string(name));
        return reinterpret_cast<T>(address);
    }
    HMODULE handle{};
};

bool writableProtection(DWORD protection) {
    protection &= 0xff;
    return protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
}

int basic(const std::filesystem::path& path) {
    const auto bytes = readFile(path);
    NativeModule native(path);
    using Add = int (*)(int, int);
    require(native.get<Add>("BasicAdd")(20, 22) == 42, "Native BasicAdd failed");
    auto module = pe::PeLoader::load(bytes);
    const auto add = module.getExport<Add>("BasicAdd");
    require(add(19, 23) == 42, "Manual BasicAdd failed");
    require(module.getExport<Add>(11)(21, 21) == 42, "Manual export-by-ordinal lookup failed");
    require(module.getExport<int (*)()>("RelocatedValue")() == 17, "Relocated global pointer failed");
    MEMORY_BASIC_INFORMATION memory{};
    require(::VirtualQuery(reinterpret_cast<void*>(add), &memory, sizeof(memory)) == sizeof(memory),
        "VirtualQuery failed");
    require(!writableProtection(memory.Protect), "Code page remained writable after initialization");
    return 0;
}

int relocation(const std::filesystem::path& path) {
    const auto bytes = readFile(path);
    const auto info = pe::PeLoader::inspect(bytes);
    void* blocker = ::VirtualAlloc(reinterpret_cast<void*>(static_cast<std::uintptr_t>(info.preferredImageBase)),
        info.imageSize, MEM_RESERVE, PAGE_NOACCESS);
    auto module = pe::PeLoader::load(bytes);
    require(reinterpret_cast<std::uintptr_t>(module.baseAddress()) != info.preferredImageBase,
        "The relocation test did not force a non-preferred base");
    if (blocker != nullptr) ::VirtualFree(blocker, 0, MEM_RELEASE);
    require(module.getExport<std::uint64_t (*)()>("RelocationValue")() == 0x123456789abcdef0ULL,
        "DIR64 relocation produced the wrong global value");
    const auto pointer = module.getExport<const void* (*)()>("RelocationPointer")();
    const auto begin = reinterpret_cast<std::uintptr_t>(module.baseAddress());
    const auto value = reinterpret_cast<std::uintptr_t>(pointer);
    require(value >= begin && value < begin + module.imageSize(), "Relocated pointer lies outside the image");
    return 0;
}

int namedImport(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("UseNamedImport")() == 43, "Native named import failed");
    auto module = pe::PeLoader::load(readFile(path));
    require(module.getExport<int (*)()>("UseNamedImport")() == 43, "Manual named import failed");
    return 0;
}

int ordinalImport(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("UseOrdinalImport")() == 42, "Native ordinal import failed");
    auto module = pe::PeLoader::load(readFile(path));
    require(module.getExport<int (*)()>("UseOrdinalImport")() == 42, "Manual ordinal import failed");
    return 0;
}

int forwarded(const std::filesystem::path& path) {
    NativeModule native(path);
    native.get<void(WINAPI*)(DWORD)>("ForwardedSleep")(0);
    auto module = pe::PeLoader::load(readFile(path));
    module.getExport<void(WINAPI*)(DWORD)>("ForwardedSleep")(0);
    return 0;
}

int tls(const std::filesystem::path& path) {
    // Windows does not invoke callbacks for this deliberately zero-length TLS
    // template. The manual loader supports the metadata-only callback case and
    // this fixture ensures it is not mistaken for compiler-managed storage.
    {
        NativeModule native(path);
        require(native.get<LONG (*)()>("TlsCallbackState")() == 0,
            "Native zero-length TLS behavior changed; revisit the callback-only fixture");
    }
    auto module = pe::PeLoader::load(readFile(path));
    require(module.getExport<LONG (*)()>("TlsCallbackState")() == 3, "Manual TLS callback ordering failed");
    return 0;
}

int staticTls(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("StaticTlsValue")() == 10, "Native static TLS value failed");
    require(native.get<int (*)()>("StaticTlsThreadIsolation")() == 1, "Native static TLS isolation failed");
    try {
        auto module = pe::PeLoader::load(readFile(path));
        (void)module;
    } catch (const pe::PeError& error) {
        require(error.code() == pe::PeErrorCode::StaticTlsUnsupported,
            "Static TLS failed with the wrong structured error");
        return 0;
    }
    throw std::runtime_error("Static TLS was silently accepted despite lacking documented registration support");
}

int zeroStaticTlsDetection(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("ZeroTlsIsInitiallyZero")() == 1,
        "Native zero-initialized TLS did not start at zero");

    const auto bytes = readFile(path);
    require(bytes.size() >= sizeof(IMAGE_DOS_HEADER), "Zero-TLS fixture has no DOS header");
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    require(dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew >= 0,
        "Zero-TLS fixture has an invalid DOS header");
    const auto ntOffset = static_cast<std::size_t>(dos->e_lfanew);
    require(ntOffset <= bytes.size() && sizeof(IMAGE_NT_HEADERS64) <= bytes.size() - ntOffset,
        "Zero-TLS fixture has an invalid NT-header offset");
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes.data() + ntOffset);

    const auto rvaToFileOffset = [&](std::uint32_t rva, std::size_t length) -> std::size_t {
        if (rva < nt->OptionalHeader.SizeOfHeaders) {
            require(rva <= bytes.size() && length <= bytes.size() - rva,
                "Zero-TLS header range is outside the fixture");
            return rva;
        }
        const auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
            if (rva >= section[index].VirtualAddress) {
                const auto delta = static_cast<std::size_t>(rva - section[index].VirtualAddress);
                if (delta <= section[index].SizeOfRawData &&
                    length <= section[index].SizeOfRawData - delta) {
                    const auto offset = static_cast<std::size_t>(section[index].PointerToRawData) + delta;
                    require(offset <= bytes.size() && length <= bytes.size() - offset,
                        "Zero-TLS section range is outside the fixture");
                    return offset;
                }
            }
        }
        throw std::runtime_error("Zero-TLS RVA has no file backing");
    };

    const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    require(directory.VirtualAddress != 0 && directory.Size >= sizeof(IMAGE_TLS_DIRECTORY64),
        "Zero-TLS fixture has no IMAGE_TLS_DIRECTORY64");
    const auto directoryOffset = rvaToFileOffset(directory.VirtualAddress, sizeof(IMAGE_TLS_DIRECTORY64));
    IMAGE_TLS_DIRECTORY64 tls{};
    std::memcpy(&tls, bytes.data() + directoryOffset, sizeof(tls));
    require(tls.EndAddressOfRawData > tls.StartAddressOfRawData,
        "Zero-TLS fixture has no raw static-TLS template");
    require(tls.SizeOfZeroFill == 0,
        "Zero-TLS regression fixture unexpectedly uses SizeOfZeroFill");
    require(tls.StartAddressOfRawData >= nt->OptionalHeader.ImageBase &&
            tls.EndAddressOfRawData >= nt->OptionalHeader.ImageBase,
        "Zero-TLS template VA precedes the image base");
    const auto rawLength64 = tls.EndAddressOfRawData - tls.StartAddressOfRawData;
    require(rawLength64 <= SIZE_MAX, "Zero-TLS raw template is too large");
    const auto rawLength = static_cast<std::size_t>(rawLength64);
    const auto rawRva64 = tls.StartAddressOfRawData - nt->OptionalHeader.ImageBase;
    require(rawRva64 <= UINT32_MAX, "Zero-TLS raw-template RVA overflows");
    const auto rawOffset = rvaToFileOffset(static_cast<std::uint32_t>(rawRva64), rawLength);
    require(std::all_of(bytes.begin() + rawOffset, bytes.begin() + rawOffset + rawLength,
                [](std::byte value) { return value == std::byte{}; }),
        "Zero-TLS regression fixture raw template is not entirely zero");

    try {
        auto module = pe::PeLoader::load(bytes);
        (void)module;
    } catch (const pe::PeError& error) {
        require(error.code() == pe::PeErrorCode::StaticTlsUnsupported,
            "Zero-initialized static TLS failed with the wrong structured error");
        return 0;
    }
    throw std::runtime_error("All-zero static TLS was silently accepted");
}

int basicStaticTlsUnsupported(const std::filesystem::path& path) {
    constexpr std::uint64_t initial = 0x1234567812345678ULL;
    using Read = std::uint64_t (*)();
    using Write = void (*)(std::uint64_t);
    using Address = std::uintptr_t (*)();
    {
        NativeModule native(path);
        const auto read = native.get<Read>("ReadTlsValue");
        const auto write = native.get<Write>("WriteTlsValue");
        const auto address = native.get<Address>("AddressOfTlsValue");
        require(read() == initial, "Native initialized TLS value is wrong");
        require(address() == address(), "Native same-thread TLS address changed");
        write(0x8877665544332211ULL);
        require(read() == 0x8877665544332211ULL, "Native TLS mutation failed");
    }

    try {
        auto module = pe::PeLoader::load(readFile(path));
        (void)module;
    } catch (const pe::PeError& error) {
        require(error.code() == pe::PeErrorCode::StaticTlsUnsupported,
            "Basic static TLS failed with the wrong structured error");
        return 0;
    }
    throw std::runtime_error("Basic compiler-generated static TLS was silently accepted");
}

int tlsAllocAbiProbe(const std::filesystem::path& path) {
    constexpr std::uint64_t initial = 0x1234567812345678ULL;
    NativeModule native(path);
    const auto addressOfValue = native.get<std::uintptr_t (*)()>("AddressOfTlsValue");

    const auto* base = reinterpret_cast<const std::byte*>(native.handle);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    require(dos->e_magic == IMAGE_DOS_SIGNATURE, "ABI probe native image has no DOS header");
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    require(directory.VirtualAddress != 0 && directory.Size >= sizeof(IMAGE_TLS_DIRECTORY64),
        "ABI probe native image has no TLS directory");
    const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(base + directory.VirtualAddress);
    require(tls->EndAddressOfRawData > tls->StartAddressOfRawData && tls->AddressOfIndex != 0,
        "ABI probe native image has no compiler static TLS");
    const auto rawSize = static_cast<std::size_t>(tls->EndAddressOfRawData - tls->StartAddressOfRawData);
    const auto* raw = reinterpret_cast<const std::byte*>(tls->StartAddressOfRawData);
    std::array<std::byte, sizeof(initial)> needle{};
    std::memcpy(needle.data(), &initial, sizeof(initial));
    const auto valuePosition = std::search(raw, raw + rawSize, needle.begin(), needle.end());
    require(valuePosition != raw + rawSize, "ABI probe could not locate its initialized TLS scalar");
    const auto valueOffset = static_cast<std::size_t>(valuePosition - raw);

    std::vector<DWORD> allocatedIndices;
    DWORD dynamicIndex = TLS_OUT_OF_INDEXES;
    auto* staticIndexSlot = reinterpret_cast<DWORD*>(tls->AddressOfIndex);
    const DWORD originalStaticIndex = *staticIndexSlot;
    for (int attempt = 0; attempt < 4; ++attempt) {
        const DWORD candidate = ::TlsAlloc();
        require(candidate != TLS_OUT_OF_INDEXES, "TlsAlloc failed during ABI probe");
        allocatedIndices.push_back(candidate);
        if (candidate != originalStaticIndex) {
            dynamicIndex = candidate;
            break;
        }
    }
    require(dynamicIndex != TLS_OUT_OF_INDEXES,
        "ABI probe could not obtain an index distinct from the native static index");

    std::vector<std::byte> dynamicBlock(rawSize + tls->SizeOfZeroFill);
    std::memcpy(dynamicBlock.data(), raw, rawSize);
    require(::TlsSetValue(dynamicIndex, dynamicBlock.data()) != FALSE,
        "TlsSetValue failed during ABI probe");
    require(::TlsGetValue(dynamicIndex) == dynamicBlock.data(),
        "TlsGetValue did not return the block installed by the ABI probe");

    *staticIndexSlot = dynamicIndex;
    const auto generatedAddress = addressOfValue();
    *staticIndexSlot = originalStaticIndex;
    for (const DWORD index : allocatedIndices) (void)::TlsFree(index);

    const auto dynamicTlsApiAddress =
        reinterpret_cast<std::uintptr_t>(dynamicBlock.data() + valueOffset);
    require(generatedAddress != dynamicTlsApiAddress,
        "TlsSetValue unexpectedly populated the PE loader static-TLS vector; revisit the architecture result");
    require(addressOfValue() != 0, "Restoring the native static TLS index failed");
    return 0;
}

int productionStaticTlsUnsupported(const std::filesystem::path& path) {
    {
        NativeModule native(path);
        if (const auto abiAddress = ::GetProcAddress(native.handle, "CoboModule_AbiVersion");
            abiAddress != nullptr) {
            const auto abiVersion = reinterpret_cast<std::uint32_t (*)()>(abiAddress);
            require(abiVersion() == 2, "Production DLL returned an unexpected safe ABI version");
        }
    }
    try {
        auto module = pe::PeLoader::load(readFile(path));
        (void)module;
    } catch (const pe::PeError& error) {
        require(error.code() == pe::PeErrorCode::StaticTlsUnsupported,
            "Production static TLS failed with the wrong structured error");
        return 0;
    }
    throw std::runtime_error("Production static TLS was accepted without loader integration");
}

int exceptionTest(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("RunExceptionTest")() == 1, "Native exception test failed");
    const auto bytes = readFile(path);
    const auto info = pe::PeLoader::inspect(bytes);
    void* blocker = ::VirtualAlloc(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(info.preferredImageBase)),
        info.imageSize, MEM_RESERVE, PAGE_NOACCESS);
    auto module = pe::PeLoader::load(bytes);
    require(reinterpret_cast<std::uintptr_t>(module.baseAddress()) != info.preferredImageBase,
        "Exception fixture was not relocated away from its preferred base");
    if (blocker != nullptr) ::VirtualFree(blocker, 0, MEM_RELEASE);
    const auto run = module.getExport<int (*)()>("RunExceptionTest");
    DWORD64 unwindBase{};
    const auto runtimeFunction = ::RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(run), &unwindBase, nullptr);
    // The exported address can be a leaf ILT jump thunk and legitimately have no entry.
    (void)runtimeFunction;
    const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(module.baseAddress());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        static_cast<const std::byte*>(module.baseAddress()) + dos->e_lfanew);
    const auto exceptionDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    const auto* table = reinterpret_cast<const RUNTIME_FUNCTION*>(
        static_cast<const std::byte*>(module.baseAddress()) + exceptionDirectory.VirtualAddress);
    DWORD64 tableBase{};
    const auto tableLookup = ::RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(module.baseAddress()) + table[0].BeginAddress,
        &tableBase, nullptr);
    require(tableLookup != nullptr, "RtlLookupFunctionEntry did not find a registered runtime function");
    require(run() == 1,
        "Manual x64 exception/unwind test failed");
    module.unload();
    return 0;
}

int constructors(const std::filesystem::path& path) {
    g_destructorCalls = 0;
    auto module = pe::PeLoader::load(readFile(path));
    require(module.getExport<int (*)()>("ConstructorState")() == 1, "Global constructor did not run");
    module.getExport<void (*)(void (*)())>("SetDestructionCallback")(&destructionObserved);
    module.unload();
    require(g_destructorCalls == 1, "Global destructor was not observed during unload");
    return 0;
}

int delayImport(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("UseDelayImport")() == 0x5a17, "Native delay import failed");
    auto module = pe::PeLoader::load(readFile(path));
    require(module.getExport<int (*)()>("UseDelayImport")() == 0x5a17, "Manual delay import failed");
    return 0;
}

int resource(const std::filesystem::path& path) {
    NativeModule native(path);
    constexpr std::uint16_t rawDataResourceType = 10;
    HRSRC nativeResource = ::FindResourceW(
        native.handle, MAKEINTRESOURCEW(101), MAKEINTRESOURCEW(rawDataResourceType));
    require(nativeResource != nullptr && ::SizeofResource(native.handle, nativeResource) != 0,
        "Native resource lookup failed");
    auto module = pe::PeLoader::load(readFile(path));
    const auto payload = module.getResource(rawDataResourceType, 101);
    const std::string text(reinterpret_cast<const char*>(payload.data()), payload.size());
    require(text.starts_with("memory-resource-payload"), "Loader-side resource contents are wrong");
    return 0;
}

int threading(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("RunThreadTest")() == 1, "Native threading test failed");
    auto module = pe::PeLoader::load(readFile(path));
    require(module.getExport<int (*)()>("RunThreadTest")() == 1, "Manual threading test failed");
    return 0;
}

int cfg(const std::filesystem::path& path) {
    NativeModule native(path);
    require(native.get<int (*)()>("RunCfgIndirectCall")() == 42, "Native CFG indirect call failed");
    try {
        auto module = pe::PeLoader::load(readFile(path));
        (void)module;
    } catch (const pe::PeError& error) {
        require(error.code() == pe::PeErrorCode::UnsupportedFeature,
            "CFG fixture failed with the wrong structured error");
        return 0;
    }
    throw std::runtime_error("CFG-instrumented DLL was silently accepted without loader registration");
}

std::uint64_t runComplexNative(const std::filesystem::path& path) {
    NativeModule native(path);
    ModuleContext context{1, L"native", 0xffff};
    require(native.get<bool (*)(const ModuleContext*)>("ModuleInitialize")(&context), "Native initialize failed");
    require(native.get<int (*)()>("ModuleRun")() == 42, "Native ModuleRun failed");
    TestReport report{};
    const auto result = native.get<std::uint64_t (*)(TestReport*)>("RunComprehensiveSelfTest")(&report);
    native.get<void (*)()>("ModuleShutdown")();
    require(report.failed == 0, "Native complex report contains failed feature flags");
    return result;
}

std::uint64_t runComplexManual(const std::filesystem::path& path) {
    auto module = pe::PeLoader::load(readFile(path));
    ModuleContext context{1, L"manual", 0xffff};
    require(module.getExport<bool (*)(const ModuleContext*)>("ModuleInitialize")(&context), "Manual initialize failed");
    require(module.getExport<int (*)()>("ModuleRun")() == 42, "Manual ModuleRun failed");
    TestReport report{};
    const auto result = module.getExport<std::uint64_t (*)(TestReport*)>("RunComprehensiveSelfTest")(&report);
    module.getExport<void (*)()>("ModuleShutdown")();
    require(report.failed == 0, "Manual complex report contains failed feature flags");
    return result;
}

int complex(const std::filesystem::path& path) {
    const auto result = runComplexManual(path);
    require(result == (1ULL << 12) - 1, "Complex DLL did not exercise every declared feature");
    return 0;
}

int compare(const std::filesystem::path& path) {
    require(runComplexNative(path) == runComplexManual(path),
        "LoadLibrary and PeLoader produced different complex feature masks");
    return 0;
}

int repeated(const std::filesystem::path& path) {
    const auto bytes = readFile(path);
    for (int i = 0; i < 100; ++i) {
        auto module = pe::PeLoader::load(bytes);
        require(module.getExport<int (*)(int, int)>("BasicAdd")(i, 42 - i) == 42,
            "Repeated load/unload returned a wrong result");
    }
    return 0;
}

int invalid(const std::filesystem::path& path) {
    const auto valid = readFile(path);
    auto mustReject = [](const std::vector<std::byte>& bytes) {
        try {
            (void)pe::PeLoader::inspect(bytes);
        } catch (const pe::PeError&) {
            return;
        }
        throw std::runtime_error("Malformed PE input was accepted");
    };
    mustReject({});
    for (std::size_t length = 1; length < (std::min<std::size_t>)(valid.size(), 1024); length += 17) {
        mustReject(std::vector<std::byte>(valid.begin(), valid.begin() + length));
    }
    auto mutation = valid;
    mutation[0] = std::byte{0};
    mustReject(mutation);
    mutation = valid;
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, mutation.data(), sizeof(dos));
    dos.e_lfanew = LONG_MAX;
    std::memcpy(mutation.data(), &dos, sizeof(dos));
    mustReject(mutation);

    auto ntHeaders = [](std::vector<std::byte>& bytes) -> IMAGE_NT_HEADERS64* {
        auto* mutableDos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
        return reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + mutableDos->e_lfanew);
    };
    auto rvaToFileOffset = [&](const std::vector<std::byte>& bytes, std::uint32_t rva) -> std::size_t {
        const auto* imageDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes.data() + imageDos->e_lfanew);
        if (rva < nt->OptionalHeader.SizeOfHeaders) return rva;
        const auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (rva >= section[i].VirtualAddress &&
                rva - section[i].VirtualAddress < section[i].SizeOfRawData) {
                return section[i].PointerToRawData + (rva - section[i].VirtualAddress);
            }
        }
        throw std::runtime_error("Fixture RVA does not have file backing");
    };
    auto mustRejectLoad = [&](const std::vector<std::byte>& bytes, std::string_view label, bool blockPreferred = false) {
        void* blocker{};
        if (blockPreferred) {
            const auto info = pe::PeLoader::inspect(bytes);
            blocker = ::VirtualAlloc(
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(info.preferredImageBase)),
                info.imageSize, MEM_RESERVE, PAGE_NOACCESS);
            require(blocker != nullptr, "Could not reserve the preferred base for malformed relocation test");
        }
        try {
            auto module = pe::PeLoader::load(bytes);
            (void)module;
        } catch (const pe::PeError&) {
            if (blocker != nullptr) ::VirtualFree(blocker, 0, MEM_RELEASE);
            return;
        }
        if (blocker != nullptr) ::VirtualFree(blocker, 0, MEM_RELEASE);
        throw std::runtime_error("Malformed mapped PE input was accepted: " + std::string(label));
    };

    mutation = valid;
    ntHeaders(mutation)->OptionalHeader.SizeOfImage = 0;
    mustReject(mutation);
    mutation = valid;
    ntHeaders(mutation)->FileHeader.NumberOfSections = 0xffff;
    mustReject(mutation);
    mutation = valid;
    IMAGE_FIRST_SECTION(ntHeaders(mutation))->PointerToRawData = UINT32_MAX;
    mustReject(mutation);
    mutation = valid;
    auto& badImport = ntHeaders(mutation)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    badImport.Size = 1;
    mustRejectLoad(mutation, "short import directory");
    mutation = valid;
    auto& badException = ntHeaders(mutation)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    badException.Size = 1;
    mustRejectLoad(mutation, "mis-sized exception directory");
    mutation = valid;
    auto* tlsNt = ntHeaders(mutation);
    const auto* tlsSections = IMAGE_FIRST_SECTION(tlsNt);
    const std::size_t tlsRva = reinterpret_cast<const std::byte*>(tlsSections + tlsNt->FileHeader.NumberOfSections) -
        mutation.data();
    require(tlsRva + sizeof(IMAGE_TLS_DIRECTORY64) <= tlsNt->OptionalHeader.SizeOfHeaders,
        "Fixture has no header slack for malformed TLS directory");
    IMAGE_TLS_DIRECTORY64 invalidTls{};
    invalidTls.StartAddressOfRawData = tlsNt->OptionalHeader.ImageBase + 0x2000;
    invalidTls.EndAddressOfRawData = invalidTls.StartAddressOfRawData - 1;
    std::memcpy(mutation.data() + tlsRva, &invalidTls, sizeof(invalidTls));
    tlsNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
        static_cast<DWORD>(tlsRva), sizeof(IMAGE_TLS_DIRECTORY64)};
    mustRejectLoad(mutation, "reversed TLS template");
    mutation = valid;
    tlsNt = ntHeaders(mutation);
    invalidTls = {};
    invalidTls.StartAddressOfRawData = tlsNt->OptionalHeader.ImageBase + 0x2000;
    invalidTls.EndAddressOfRawData = invalidTls.StartAddressOfRawData + sizeof(std::uint64_t);
    std::memcpy(mutation.data() + tlsRva, &invalidTls, sizeof(invalidTls));
    tlsNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
        static_cast<DWORD>(tlsRva), sizeof(IMAGE_TLS_DIRECTORY64)};
    mustRejectLoad(mutation, "static TLS without AddressOfIndex");
    mutation = valid;
    tlsNt = ntHeaders(mutation);
    invalidTls.AddressOfIndex = tlsNt->OptionalHeader.ImageBase + tlsRva;
    std::memcpy(mutation.data() + tlsRva, &invalidTls, sizeof(invalidTls));
    tlsNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
        static_cast<DWORD>(tlsRva), sizeof(IMAGE_TLS_DIRECTORY64)};
    mustRejectLoad(mutation, "TLS index in non-writable headers");
    mutation = valid;
    tlsNt = ntHeaders(mutation);
    invalidTls = {};
    invalidTls.Characteristics = 0x00f00000;
    std::memcpy(mutation.data() + tlsRva, &invalidTls, sizeof(invalidTls));
    tlsNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
        static_cast<DWORD>(tlsRva), sizeof(IMAGE_TLS_DIRECTORY64)};
    mustRejectLoad(mutation, "invalid TLS alignment encoding");
    mutation = valid;
    tlsNt = ntHeaders(mutation);
    invalidTls.Characteristics = 1;
    std::memcpy(mutation.data() + tlsRva, &invalidTls, sizeof(invalidTls));
    tlsNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
        static_cast<DWORD>(tlsRva), sizeof(IMAGE_TLS_DIRECTORY64)};
    mustRejectLoad(mutation, "reserved TLS Characteristics bits");
    mutation = valid;
    tlsNt = ntHeaders(mutation);
    invalidTls = {};
    invalidTls.StartAddressOfRawData = tlsNt->OptionalHeader.ImageBase + tlsNt->OptionalHeader.SizeOfImage + 1;
    invalidTls.EndAddressOfRawData = invalidTls.StartAddressOfRawData;
    std::memcpy(mutation.data() + tlsRva, &invalidTls, sizeof(invalidTls));
    tlsNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
        static_cast<DWORD>(tlsRva), sizeof(IMAGE_TLS_DIRECTORY64)};
    mustRejectLoad(mutation, "out-of-image empty TLS template marker");
    mutation = valid;
    const auto relocationRva =
        ntHeaders(mutation)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    auto* relocationBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        mutation.data() + rvaToFileOffset(mutation, relocationRva));
    relocationBlock->SizeOfBlock = UINT32_MAX;
    mustRejectLoad(mutation, "overflowing relocation block", true);

    std::mt19937 generator(0x5045);
    for (int sample = 0; sample < 64; ++sample) {
        std::vector<std::byte> random(static_cast<std::size_t>(sample * 13 + 1));
        for (auto& value : random) value = static_cast<std::byte>(generator() & 0xff);
        mustReject(random);
    }
    return 0;
}

int parallel(const std::filesystem::path& path) {
    const auto bytes = readFile(path);
    std::vector<std::future<int>> tasks;
    for (int i = 0; i < 8; ++i) {
        tasks.push_back(std::async(std::launch::async, [&bytes, i] {
            auto module = pe::PeLoader::load(bytes);
            return module.getExport<int (*)(int, int)>("BasicAdd")(i, 42 - i);
        }));
    }
    for (auto& task : tasks) require(task.get() == 42, "Parallel load returned a wrong result");
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (argc != 3) {
        std::cerr << "Usage: pe_loader_tests <mode> <fixture.dll>\n";
        return 2;
    }
    try {
        const std::string mode = std::filesystem::path(argv[1]).string();
        const std::filesystem::path path = argv[2];
        if (mode == "basic") return basic(path);
        if (mode == "relocation") return relocation(path);
        if (mode == "import") return namedImport(path);
        if (mode == "ordinal") return ordinalImport(path);
        if (mode == "forwarded") return forwarded(path);
        if (mode == "tls") return tls(path);
        if (mode == "static_tls") return staticTls(path);
        if (mode == "zero_static_tls_detection") return zeroStaticTlsDetection(path);
        if (mode == "basic_static_tls_unsupported") return basicStaticTlsUnsupported(path);
        if (mode == "tls_alloc_abi_probe") return tlsAllocAbiProbe(path);
        if (mode == "production_static_tls_unsupported") return productionStaticTlsUnsupported(path);
        if (mode == "exception") return exceptionTest(path);
        if (mode == "constructors") return constructors(path);
        if (mode == "delay") return delayImport(path);
        if (mode == "resource") return resource(path);
        if (mode == "threading") return threading(path);
        if (mode == "cfg") return cfg(path);
        if (mode == "complex") return complex(path);
        if (mode == "repeat") return repeated(path);
        if (mode == "invalid") return invalid(path);
        if (mode == "compare") return compare(path);
        if (mode == "parallel") return parallel(path);
        throw std::runtime_error("Unknown test mode: " + mode);
    } catch (const pe::PeError& error) {
        std::cerr << "PeError(" << static_cast<int>(error.code()) << "): " << error.what()
                  << " [Win32=" << error.systemError() << "]\n";
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
    }
    return 1;
}
