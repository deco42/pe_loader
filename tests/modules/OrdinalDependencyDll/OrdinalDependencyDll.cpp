#include <Windows.h>

extern "C" int WINAPI OrdinalMultiply(int a, int b) { return a * b; }
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
