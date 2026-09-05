#include <Windows.h>

extern "C" __declspec(dllexport) int DependencyAdd(int a, int b) { return a + b; }
extern "C" __declspec(dllexport) int DependencyMagic() { return 0x5a17; }
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
