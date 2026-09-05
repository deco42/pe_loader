#include <Windows.h>

extern "C" __declspec(dllimport) int WINAPI OrdinalMultiply(int, int);
extern "C" __declspec(dllexport) int UseOrdinalImport() { return OrdinalMultiply(6, 7); }
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
