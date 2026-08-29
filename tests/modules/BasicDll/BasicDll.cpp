#include <Windows.h>

#include <cstdint>

namespace {
int g_value = 17;
int* g_relocatedPointer = &g_value;
} // namespace

extern "C" __declspec(dllexport) int BasicAdd(int a, int b) { return a + b; }
extern "C" __declspec(dllexport) int RelocatedValue() { return *g_relocatedPointer; }
extern "C" __declspec(dllexport) std::uintptr_t ReportedImageBase() {
    HMODULE self{};
    ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&ReportedImageBase), &self);
    return reinterpret_cast<std::uintptr_t>(self);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
