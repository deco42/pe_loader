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
