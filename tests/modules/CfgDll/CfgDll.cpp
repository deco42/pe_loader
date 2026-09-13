#include <Windows.h>

namespace {
int addOne(int value) { return value + 1; }
} // namespace

extern "C" __declspec(dllexport) int RunCfgIndirectCall() {
    volatile auto function = &addOne;
    return function(41);
}
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
