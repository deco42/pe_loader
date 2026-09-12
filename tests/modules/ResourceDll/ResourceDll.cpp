#include <Windows.h>

extern "C" __declspec(dllexport) int ResourceDllReady() { return 1; }
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
