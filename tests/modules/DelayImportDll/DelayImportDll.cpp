#include <Windows.h>

extern "C" __declspec(dllimport) int DependencyMagic();
extern "C" __declspec(dllexport) int UseDelayImport() { return DependencyMagic(); }
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
