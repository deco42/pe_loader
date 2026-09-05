#include <Windows.h>

extern "C" __declspec(dllimport) int DependencyAdd(int, int);
extern "C" __declspec(dllexport) int UseNamedImport() {
    return DependencyAdd(19, 23) + static_cast<int>(::GetCurrentProcessId() != 0);
}
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
