#pragma once

#include <cstddef>
#include <cstdint>

namespace tls_research {

inline constexpr std::uint32_t kApiVersion = 1;
inline constexpr std::uint32_t kEventCapacity = 512;
inline constexpr std::uint64_t kInitialScalar = 0x1122334455667788ULL;

enum class FixtureKind : std::uint32_t {
    Scalar = 1,
    CppObject = 2,
    LargeAligned = 3,
    MultipleObjects = 4,
    Destructor = 5,
    Threaded = 6,
};

enum class EventKind : std::uint32_t {
    TlsCallbackProcessAttach = 1,
    TlsCallbackThreadAttach = 2,
    TlsCallbackThreadDetach = 3,
    TlsCallbackProcessDetach = 4,
    GlobalConstructor = 5,
    GlobalDestructor = 6,
    TlsObjectConstructor = 7,
    TlsObjectDestructor = 8,
    DllMainProcessAttach = 9,
    DllMainThreadAttach = 10,
    DllMainThreadDetach = 11,
    DllMainProcessDetach = 12,
    ExportEnter = 13,
    InternalThreadEnter = 14,
    FunctionLocalInitializer = 15,
};

struct EventRecord {
    std::uint64_t sequence{};
    std::uint32_t threadId{};
    EventKind kind{};
    std::uintptr_t tlsAddress{};
    std::uint32_t tlsIndex{};
    std::uint32_t reserved{};
    std::uint64_t value{};
};

// POD storage supplied by the probe. The DLL only performs interlocked updates
// and fixed-size copies, so the ABI does not cross a CRT heap boundary.
struct alignas(8) SharedEventBuffer {
    volatile long long nextSequence{};
    volatile long writeCount{};
    std::uint32_t capacity{kEventCapacity};
    EventRecord records[kEventCapacity]{};
};

using GetApiVersionFn = std::uint32_t (*)();
using GetFixtureKindFn = std::uint32_t (*)();
using SetEventBufferFn = int (*)(SharedEventBuffer*, std::size_t);
using ReadTlsValueFn = std::uint64_t (*)();
using WriteTlsValueFn = void (*)(std::uint64_t);
using GetTlsAddressFn = std::uintptr_t (*)();
using GetCompilerTlsIndexFn = std::uint32_t (*)();
using TouchCppObjectFn = std::uint64_t (*)();
using TouchFunctionLocalFn = std::uint64_t (*)();
using GetSecondaryTlsAddressFn = std::uintptr_t (*)();
using GetLargeTlsAddressFn = std::uintptr_t (*)();
using GetLargeTlsSizeFn = std::size_t (*)();
using RunInternalThreadFn = int (*)();
using RunExternalThreadFn = int (*)(void*, std::uint64_t, std::uint64_t);

} // namespace tls_research
