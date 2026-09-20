#include "pe_loader/PeLoader.hpp"
#include "ModuleApi.hpp"

#include <Windows.h>

#include <algorithm>
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
        if (mode == "delay") return delayImport(path);
        if (mode == "resource") return resource(path);
        if (mode == "cfg") return cfg(path);
        if (mode == "repeat") return repeated(path);
        if (mode == "invalid") return invalid(path);
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
