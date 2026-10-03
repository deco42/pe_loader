#include <Windows.h>

#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace {
using DestructionCallback = void (*)();
DestructionCallback g_callback{};

struct GlobalObject {
    GlobalObject() : values{"constructed", std::filesystem::path(L"module").string()} {}
    ~GlobalObject() {
        if (g_callback != nullptr) g_callback();
    }
    std::vector<std::string> values;
    std::mutex mutex;
};

GlobalObject g_object;
} // namespace

extern "C" __declspec(dllexport) int ConstructorState() {
    std::scoped_lock lock(g_object.mutex);
    return g_object.values.size() == 2 && g_object.values.front() == "constructed";
}
extern "C" __declspec(dllexport) void SetDestructionCallback(DestructionCallback callback) {
    g_callback = callback;
}
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
