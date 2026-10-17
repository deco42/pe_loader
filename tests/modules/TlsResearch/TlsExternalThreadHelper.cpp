#include "TlsResearchApi.hpp"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <thread>

extern "C" __declspec(dllexport) int RunTlsExternalThread(
    void* targetModule, std::uint64_t expectedInitial, std::uint64_t writeValue) {
    if (targetModule == nullptr) return FALSE;

    const auto module = static_cast<HMODULE>(targetModule);
    const auto read = reinterpret_cast<tls_research::ReadTlsValueFn>(
        ::GetProcAddress(module, "ReadTlsValue"));
    const auto write = reinterpret_cast<tls_research::WriteTlsValueFn>(
        ::GetProcAddress(module, "WriteTlsValue"));
    const auto address = reinterpret_cast<tls_research::GetTlsAddressFn>(
        ::GetProcAddress(module, "GetTlsAddress"));
    const auto touchObject = reinterpret_cast<tls_research::TouchCppObjectFn>(
        ::GetProcAddress(module, "TouchCppObject"));
    const auto touchFunctionLocal = reinterpret_cast<tls_research::TouchFunctionLocalFn>(
        ::GetProcAddress(module, "TouchFunctionLocal"));
    if (read == nullptr || write == nullptr || address == nullptr ||
        touchObject == nullptr || touchFunctionLocal == nullptr) {
        return FALSE;
    }

    try {
        std::atomic<bool> passed{false};
        std::thread worker([&] {
            const bool initialized = address() != 0 && read() == expectedInitial;
            write(writeValue);
            const bool isolatedWrite = read() == writeValue;
            const bool objectWorked = touchObject() != 0;
            const bool localWorked = touchFunctionLocal() != 0;
            passed.store(initialized && isolatedWrite && objectWorked && localWorked,
                std::memory_order_release);
        });
        worker.join();
        return passed.load(std::memory_order_acquire) ? TRUE : FALSE;
    } catch (...) {
        return FALSE;
    }
}
