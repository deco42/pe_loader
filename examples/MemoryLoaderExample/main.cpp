#include "pe_loader/PeLoader.hpp"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

struct ModuleContext {
    std::uint32_t apiVersion;
    const wchar_t* userName;
    std::uint64_t permissions;
};

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::wcerr << L"Usage: memory_loader_example <module.dll>\n";
        return 2;
    }
    try {
        std::ifstream stream(std::filesystem::path(argv[1]), std::ios::binary);
        if (!stream) throw std::runtime_error("Could not open the DLL");
        std::vector<char> raw{std::istreambuf_iterator<char>(stream), {}};
        std::vector<std::byte> bytes(raw.size());
        std::memcpy(bytes.data(), raw.data(), raw.size());
        stream.close();

        auto module = pe::PeLoader::load(bytes);
        using VersionFn = std::uint32_t (*)();
        using InitializeFn = bool (*)(const ModuleContext*);
        using RunFn = int (*)();
        using ShutdownFn = void (*)();
        const auto version = module.getExport<VersionFn>("ModuleApiVersion");
        const auto initialize = module.getExport<InitializeFn>("ModuleInitialize");
        const auto run = module.getExport<RunFn>("ModuleRun");
        const auto shutdown = module.getExport<ShutdownFn>("ModuleShutdown");

        ModuleContext context{version(), L"MemoryLoaderExample", 0xffff};
        if (!initialize(&context)) throw std::runtime_error("ModuleInitialize failed");
        const int result = run();
        shutdown();
        module.unload();
        std::cout << "ModuleRun returned " << result << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
