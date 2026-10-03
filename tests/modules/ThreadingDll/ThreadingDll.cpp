#include <Windows.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

extern "C" __declspec(dllexport) int RunThreadTest() {
    std::mutex mutex;
    std::condition_variable condition;
    bool ready = false;
    std::atomic<int> result = 0;
    std::jthread worker([&](std::stop_token) {
        std::unique_lock lock(mutex);
        condition.wait(lock, [&] { return ready; });
        result.store(42);
    });
    {
        std::scoped_lock lock(mutex);
        ready = true;
    }
    condition.notify_one();
    worker.join();
    return result.load() == 42;
}
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
