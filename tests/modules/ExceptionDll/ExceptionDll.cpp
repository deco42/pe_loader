#include <Windows.h>

#include <array>
#include <stdexcept>

namespace {
std::array<int, 3> g_destroyed{};
int g_destroyedCount = 0;

struct Guard {
    explicit Guard(int value) : value(value) {}
    ~Guard() { g_destroyed[static_cast<std::size_t>(g_destroyedCount++)] = value; }
    int value;
};

__declspec(noinline) void level3() {
    Guard guard(3);
    throw std::runtime_error("unwind-test");
}
__declspec(noinline) void level2() {
    Guard guard(2);
    level3();
}
__declspec(noinline) void level1() {
    Guard guard(1);
    level2();
}
} // namespace

extern "C" __declspec(dllexport) int RunExceptionTest() {
    g_destroyed = {};
    g_destroyedCount = 0;
    try {
        level1();
    } catch (const std::runtime_error& error) {
        return std::string_view(error.what()) == "unwind-test" && g_destroyedCount == 3 &&
            g_destroyed[0] == 3 && g_destroyed[1] == 2 && g_destroyed[2] == 1;
    }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
