#include <Windows.h>

#include <cstddef>

#ifdef _DEBUG
// /NODEFAULTLIB keeps this fixture free of CRT-provided static TLS. CMake's
// MSVC Debug flags still emit the RTC module hooks, which are no-ops here.
extern "C" void __cdecl _RTC_InitBase() {}
extern "C" void __cdecl _RTC_Shutdown() {}
#endif

namespace {
volatile LONG g_state = 0;
DWORD g_callbackOnlyTlsIndex = TLS_OUT_OF_INDEXES;
std::byte g_callbackOnlyTlsAnchor{};

void NTAPI tlsCallback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) ::InterlockedOr(&g_state, 1);
    if (reason == DLL_PROCESS_DETACH) ::InterlockedOr(&g_state, 4);
}
} // namespace

#pragma section(".CRT$XLA", long, read)
#pragma section(".CRT$XLB", long, read)
#pragma section(".CRT$XLZ", long, read)
extern "C" __declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK pe_tls_callback_start = nullptr;
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK pe_tls_callback = tlsCallback;
extern "C" __declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK pe_tls_callback_end = nullptr;

#pragma section(".rdata$T", long, read)
extern "C" __declspec(allocate(".rdata$T")) const IMAGE_TLS_DIRECTORY64 _tls_used = {
    reinterpret_cast<ULONGLONG>(&g_callbackOnlyTlsAnchor),
    reinterpret_cast<ULONGLONG>(&g_callbackOnlyTlsAnchor),
    reinterpret_cast<ULONGLONG>(&g_callbackOnlyTlsIndex),
    reinterpret_cast<ULONGLONG>(&pe_tls_callback),
    0,
    0,
};

#pragma comment(linker, "/INCLUDE:pe_tls_callback")
#pragma comment(linker, "/INCLUDE:_tls_used")

extern "C" __declspec(dllexport) LONG TlsCallbackState() { return g_state; }
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH && (g_state & 1) != 0) ::InterlockedOr(&g_state, 2);
    return TRUE;
}
