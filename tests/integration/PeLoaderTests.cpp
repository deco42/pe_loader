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

int repeated(const std::filesystem::path& path) {
    const auto bytes = readFile(path);
    for (int i = 0; i < 100; ++i) {
        auto module = pe::PeLoader::load(bytes);
        require(module.getExport<int (*)(int, int)>("BasicAdd")(i, 42 - i) == 42,
            "Repeated load/unload returned a wrong result");
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
        if (mode == "repeat") return repeated(path);
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
