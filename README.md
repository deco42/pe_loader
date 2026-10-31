# PE Loader

Windows PE Loader is a C++20 library for loading an AMD64 PE32+ DLL from an
existing byte buffer into the current process. It validates the input, maps the
virtual image, resolves dependencies with the Windows loader, initializes the
DLL, exposes its exports, and tears it down through an RAII handle.

## Configure, build, and test

From a Visual Studio Developer PowerShell:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure

cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Equivalent presets are available:

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-debug
ctest --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-release
```

Useful cache options are:

```text
PELOADER_BUILD_EXAMPLES=ON|OFF
PELOADER_BUILD_TESTS=ON|OFF
PELOADER_ENABLE_VERBOSE_LOGGING=ON|OFF
PELOADER_MSVC_RUNTIME=STATIC|DYNAMIC
```

`PELOADER_MSVC_RUNTIME` controls the loader and test driver. The suite always
builds explicit `/MT` and `/MD` fixture DLLs so both runtime forms are covered.

## Public API

```cpp
#include <pe_loader/PeLoader.hpp>

std::vector<std::byte> dllBytes = obtainOwnedDllBytes();
auto module = pe::PeLoader::load(dllBytes);

using Run = int (*)();
const auto run = module.getExport<Run>("ModuleRun");
const int result = run();

module.unload(); // optional; the destructor also unloads
```

The example at `examples/MemoryLoaderExample` reads a DLL, closes the file,
loads the retained byte vector, calls the fixed API, and unloads.

After a Debug build:

```powershell
build\bin\Debug\memory_loader_example.exe build\bin\Debug\ComplexCppDll.dll
```

Use a POD C ABI across the module boundary. Do not transfer ownership of STL
objects, C++ exceptions, `FILE*`, or allocations unless both sides have an
explicitly compatible runtime and ownership contract.

## Supported

Automated tests exercise PE32+ validation, sections, forced relocation,
imports by name and ordinal, delay imports, exports, TLS callbacks, x64 unwind
registration and C++ exceptions, constructors/destructors, resources through
the loader API, final page permissions, parallel instances, malformed inputs,
and repeated load/unload.
