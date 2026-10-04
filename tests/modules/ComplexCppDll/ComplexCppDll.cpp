#include "ModuleApi.hpp"

#include <Windows.h>
#include <bcrypt.h>

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

extern "C" __declspec(dllimport) int DependencyMagic();

namespace {
struct GlobalState {
    GlobalState() : words{"global", "constructor"}, lookup{{"answer", 42}} {}
    std::vector<std::string> words;
    std::unordered_map<std::string, int> lookup;
    std::mutex mutex;
};
GlobalState g_state;
std::atomic<bool> g_initialized{false};
std::wstring g_user;

struct Interface {
    virtual ~Interface() = default;
    virtual int value() const = 0;
};
struct Implementation final : Interface {
    int value() const override { return 42; }
};

struct Guard {
    explicit Guard(bool& destroyed) : destroyed(destroyed) {}
    ~Guard() { destroyed = true; }
    bool& destroyed;
};

__declspec(noinline) void nestedThrow(bool& destroyed) {
    Guard guard(destroyed);
    throw std::runtime_error("complex");
}
} // namespace

extern "C" __declspec(dllexport) std::uint32_t ModuleApiVersion() { return 1; }

extern "C" __declspec(dllexport) bool ModuleInitialize(const ModuleContext* context) {
    if (context == nullptr || context->apiVersion != 1 || context->userName == nullptr) return false;
    std::scoped_lock lock(g_state.mutex);
    g_user = context->userName;
    g_initialized.store(true);
    return true;
}

extern "C" __declspec(dllexport) int ModuleRun() {
    return g_initialized.load() ? 42 : -1;
}

extern "C" __declspec(dllexport) void ModuleShutdown() {
    std::scoped_lock lock(g_state.mutex);
    g_initialized.store(false);
    g_user.clear();
}

extern "C" __declspec(dllexport) std::uint64_t RunComprehensiveSelfTest(TestReport* report) {
    std::uint64_t passed = 0;
    if (g_state.words.size() == 2 && g_state.lookup.at("answer") == 42) {
        passed |= PE_TEST_GLOBAL_CTOR | PE_TEST_STL;
    }
    if (::GetCurrentProcessId() != 0) passed |= PE_TEST_IMPORT_KERNEL32;
    if (::GetSystemMetrics(SM_CXSCREEN) >= 0) passed |= PE_TEST_IMPORT_USER32;
    UCHAR randomByte{};
    if (BCryptGenRandom(nullptr, &randomByte, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        passed |= PE_TEST_IMPORT_BCRYPT;
    }
    bool destroyed = false;
    try {
        nestedThrow(destroyed);
    } catch (const std::runtime_error&) {
        if (destroyed) passed |= PE_TEST_EXCEPTION;
    }
    std::mutex mutex;
    std::condition_variable condition;
    bool ready = false;
    std::atomic<int> threadResult{};
    std::jthread thread([&] {
        std::unique_lock lock(mutex);
        condition.wait(lock, [&] { return ready; });
        threadResult = 1;
    });
    {
        std::scoped_lock lock(mutex);
        ready = true;
    }
    condition.notify_one();
    thread.join();
    if (threadResult == 1) passed |= PE_TEST_THREAD | PE_TEST_ATOMIC;
    if (std::filesystem::exists(std::filesystem::current_path())) passed |= PE_TEST_FILESYSTEM;
    std::unique_ptr<Interface> object = std::make_unique<Implementation>();
    if (object->value() == 42) passed |= PE_TEST_VIRTUAL_CALL;
    const auto callback = [](int value) { return value + 2; };
    if (callback(40) == 42) passed |= PE_TEST_CALLBACK;
    if (DependencyMagic() == 0x5a17) passed |= PE_TEST_DEPENDENCY;
    const std::uint64_t expected = (1ULL << 12) - 1;
    if (report != nullptr) {
        report->passed = passed;
        report->failed = expected & ~passed;
    }
    return passed;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
