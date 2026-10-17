#include "TlsResearchApi.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#ifndef TLS_RESEARCH_FIXTURE_KIND
#error TLS_RESEARCH_FIXTURE_KIND must identify the research fixture
#endif

extern "C" unsigned long _tls_index;

namespace {

using tls_research::EventKind;
using tls_research::EventRecord;
using tls_research::SharedEventBuffer;

thread_local std::uint64_t g_scalar = tls_research::kInitialScalar;

#if defined(TLS_RESEARCH_HAS_MULTIPLE)
thread_local std::uint32_t g_secondary = 0xA1B2C3D4U;
alignas(64) thread_local std::array<std::uint8_t, 96> g_multipleAligned{};
#endif

#if defined(TLS_RESEARCH_HAS_LARGE)
alignas(4096) thread_local std::array<std::uint8_t, 4096> g_largeAligned{};
#endif

SharedEventBuffer g_earlyEvents{};
SharedEventBuffer* volatile g_eventSink = &g_earlyEvents;

[[nodiscard]] std::uintptr_t scalarAddress() noexcept {
    return reinterpret_cast<std::uintptr_t>(&g_scalar);
}

void record(EventKind kind, std::uint64_t value = 0) noexcept {
    auto* const sink = static_cast<SharedEventBuffer*>(
        ::InterlockedCompareExchangePointer(
            reinterpret_cast<void* volatile*>(&g_eventSink), nullptr, nullptr));
    if (sink == nullptr || sink->capacity == 0) return;

    const long slot = ::InterlockedIncrement(
                          reinterpret_cast<volatile LONG*>(&sink->writeCount)) -
        1;
    const long long sequence = ::InterlockedIncrement64(
        reinterpret_cast<volatile LONG64*>(&sink->nextSequence));
    if (slot < 0 || static_cast<std::uint32_t>(slot) >= sink->capacity) return;

    auto& event = sink->records[slot];
    event.sequence = static_cast<std::uint64_t>(sequence);
    event.threadId = ::GetCurrentThreadId();
    event.kind = kind;
    event.tlsAddress = scalarAddress();
    event.tlsIndex = _tls_index;
    event.value = value;
}

#if defined(TLS_RESEARCH_HAS_OBJECT)
struct TrackedObject {
    std::uint64_t value{};

    TrackedObject() noexcept
        : value(0xC0B0000000000000ULL | ::GetCurrentThreadId()) {
        record(EventKind::TlsObjectConstructor, value);
    }

    ~TrackedObject() { record(EventKind::TlsObjectDestructor, value); }
};

thread_local TrackedObject g_object;
thread_local std::string g_text = "tls-research-string";
#endif

struct GlobalLifecycle {
    GlobalLifecycle() { record(EventKind::GlobalConstructor); }
    ~GlobalLifecycle() { record(EventKind::GlobalDestructor); }
};

GlobalLifecycle g_globalLifecycle;

void NTAPI tlsCallback(PVOID, DWORD reason, PVOID) noexcept {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        record(EventKind::TlsCallbackProcessAttach);
        break;
    case DLL_THREAD_ATTACH:
        record(EventKind::TlsCallbackThreadAttach);
        break;
    case DLL_THREAD_DETACH:
        record(EventKind::TlsCallbackThreadDetach);
        break;
    case DLL_PROCESS_DETACH:
        record(EventKind::TlsCallbackProcessDetach);
        break;
    default:
        break;
    }
}

} // namespace

#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK ResearchTlsCallbackEntry = tlsCallback;
#pragma comment(linker, "/INCLUDE:ResearchTlsCallbackEntry")

extern "C" __declspec(dllexport) std::uint32_t GetTlsResearchApiVersion() {
    return tls_research::kApiVersion;
}

extern "C" __declspec(dllexport) std::uint32_t GetTlsResearchFixtureKind() {
    return TLS_RESEARCH_FIXTURE_KIND;
}

extern "C" __declspec(dllexport) int SetTlsResearchEventBuffer(
    SharedEventBuffer* buffer, std::size_t size) {
    if (buffer == nullptr || size != sizeof(SharedEventBuffer) ||
        buffer->capacity != tls_research::kEventCapacity) {
        return FALSE;
    }

    const long earlyWritten = g_earlyEvents.writeCount;
    const long earlyCount = (std::min)(earlyWritten,
        static_cast<long>(tls_research::kEventCapacity));
    buffer->writeCount = earlyCount;
    buffer->nextSequence = g_earlyEvents.nextSequence;
    if (earlyCount > 0) {
        std::memcpy(buffer->records, g_earlyEvents.records,
            static_cast<std::size_t>(earlyCount) * sizeof(EventRecord));
    }
    ::InterlockedExchangePointer(
        reinterpret_cast<void* volatile*>(&g_eventSink), buffer);
    return TRUE;
}

extern "C" __declspec(dllexport) std::uint64_t ReadTlsValue() {
    record(EventKind::ExportEnter, g_scalar);
    return g_scalar;
}

extern "C" __declspec(dllexport) void WriteTlsValue(std::uint64_t value) {
    record(EventKind::ExportEnter, value);
    g_scalar = value;
}

extern "C" __declspec(dllexport) std::uintptr_t GetTlsAddress() {
    record(EventKind::ExportEnter);
    return scalarAddress();
}

extern "C" __declspec(dllexport) std::uint32_t GetCompilerTlsIndex() {
    return _tls_index;
}

extern "C" __declspec(dllexport) std::uint64_t TouchCppObject() {
#if defined(TLS_RESEARCH_HAS_OBJECT)
    g_text.push_back('x');
    record(EventKind::ExportEnter, g_object.value);
    return ++g_object.value + g_text.size();
#else
    return 0;
#endif
}

extern "C" __declspec(dllexport) std::uint64_t TouchFunctionLocal() {
    static thread_local std::uint64_t value = [] {
        record(EventKind::FunctionLocalInitializer);
        return 0xD000000000000000ULL | ::GetCurrentThreadId();
    }();
    return ++value;
}

extern "C" __declspec(dllexport) std::uintptr_t GetSecondaryTlsAddress() {
#if defined(TLS_RESEARCH_HAS_MULTIPLE)
    g_multipleAligned[0] = 0x5A;
    return reinterpret_cast<std::uintptr_t>(&g_secondary);
#else
    return 0;
#endif
}

extern "C" __declspec(dllexport) std::uintptr_t GetLargeTlsAddress() {
#if defined(TLS_RESEARCH_HAS_LARGE)
    g_largeAligned[0] = 0xA5;
    return reinterpret_cast<std::uintptr_t>(g_largeAligned.data());
#else
    return 0;
#endif
}

extern "C" __declspec(dllexport) std::size_t GetLargeTlsSize() {
#if defined(TLS_RESEARCH_HAS_LARGE)
    return g_largeAligned.size();
#else
    return 0;
#endif
}

extern "C" __declspec(dllexport) int RunInternalThread() {
#if defined(TLS_RESEARCH_HAS_INTERNAL_THREAD)
    const auto parent = g_scalar;
    std::atomic<bool> passed{false};
    std::thread worker([&] {
        record(EventKind::InternalThreadEnter, g_scalar);
        const bool initialized = g_scalar == tls_research::kInitialScalar;
        g_scalar = 0x9988776655443322ULL;
#if defined(TLS_RESEARCH_HAS_OBJECT)
        const bool objectWorked = ++g_object.value != 0;
#else
        const bool objectWorked = true;
#endif
        passed.store(initialized && objectWorked, std::memory_order_release);
    });
    worker.join();
    return passed.load(std::memory_order_acquire) && g_scalar == parent;
#else
    return TRUE;
#endif
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        record(EventKind::DllMainProcessAttach);
        break;
    case DLL_THREAD_ATTACH:
        record(EventKind::DllMainThreadAttach);
        break;
    case DLL_THREAD_DETACH:
        record(EventKind::DllMainThreadDetach);
        break;
    case DLL_PROCESS_DETACH:
        record(EventKind::DllMainProcessDetach);
        break;
    default:
        break;
    }
    return TRUE;
}
