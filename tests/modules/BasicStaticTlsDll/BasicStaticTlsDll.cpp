#include <Windows.h>

#include <cstdint>

namespace {
constexpr std::uint64_t kInitialValue = 0x1234567812345678ULL;
thread_local std::uint64_t g_value = kInitialValue;
} // namespace

extern "C" __declspec(dllexport) std::uint64_t ReadTlsValue() { return g_value; }
extern "C" __declspec(dllexport) void WriteTlsValue(std::uint64_t value) { g_value = value; }
extern "C" __declspec(dllexport) std::uintptr_t AddressOfTlsValue() {
    return reinterpret_cast<std::uintptr_t>(&g_value);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
