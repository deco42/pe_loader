#include <Windows.h>

#include <cstdint>

namespace {
std::uint64_t g_value = 0x123456789abcdef0ULL;
std::uint64_t* g_pointer = &g_value;
} // namespace

extern "C" __declspec(dllexport) std::uint64_t RelocationValue() { return *g_pointer; }
extern "C" __declspec(dllexport) const void* RelocationPointer() { return g_pointer; }
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
