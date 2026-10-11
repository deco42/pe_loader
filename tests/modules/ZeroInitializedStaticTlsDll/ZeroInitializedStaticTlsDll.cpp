#include <Windows.h>

#include <cstdint>

thread_local std::uint64_t g_zeroScalar;
thread_local char g_zeroBuffer[512];

extern "C" __declspec(dllexport) int ZeroTlsIsInitiallyZero() {
    if (g_zeroScalar != 0) return 0;
    for (const char value : g_zeroBuffer) {
        if (value != 0) return 0;
    }
    return 1;
}

extern "C" __declspec(dllexport) std::uintptr_t ZeroTlsAddress() {
    return reinterpret_cast<std::uintptr_t>(&g_zeroScalar);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
