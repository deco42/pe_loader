#include <Windows.h>

#include <thread>

thread_local int g_threadValue = 10;

extern "C" __declspec(dllexport) int StaticTlsValue() { return g_threadValue; }
extern "C" __declspec(dllexport) int StaticTlsThreadIsolation() {
    int child = 0;
    std::thread worker([&] { g_threadValue = 77; child = g_threadValue; });
    worker.join();
    return child == 77 && g_threadValue == 10;
}
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
