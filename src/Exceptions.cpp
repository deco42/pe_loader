#include "PeInternal.hpp"

#include <algorithm>
#include <array>
#include <sstream>

namespace pe::detail {
namespace {

constexpr DWORD kMsvcCppException = 0xE06D7363;
constexpr ULONG_PTR kMsvcEhMagic = 0x19930520;
constexpr ULONG_PTR kMsvcEhPureMagic = 0x01994000;

struct ImageRange {
    std::uintptr_t begin;
    std::uintptr_t end;
};

struct ExceptionRouter {
    static constexpr std::size_t maximumImages = 256;
    SRWLOCK lock = SRWLOCK_INIT;
    std::array<ImageRange, maximumImages> images{};
    std::size_t imageCount{};
    void* handler{};
};

ExceptionRouter& router() {
    static ExceptionRouter instance;
    return instance;
}

LONG CALLBACK routeMsvcException(PEXCEPTION_POINTERS pointers) noexcept {
    if (pointers == nullptr || pointers->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    auto* record = pointers->ExceptionRecord;
    if (record->ExceptionCode != kMsvcCppException || record->NumberParameters != 4 ||
        record->ExceptionInformation[3] != 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto throwInfo = static_cast<std::uintptr_t>(record->ExceptionInformation[2]);
    auto& state = router();
    ::AcquireSRWLockShared(&state.lock);
    for (std::size_t index = 0; index < state.imageCount; ++index) {
        const auto& image = state.images[index];
        if (throwInfo >= image.begin && throwInfo < image.end) {
            // The MSVC runtime normally obtains this value through
            // RtlPcToFileHeader. A manual image is not in the OS loader list,
            // so supply the owning base only for throw metadata in our image.
            record->ExceptionInformation[3] = image.begin;
            if (record->ExceptionInformation[0] == kMsvcEhPureMagic) {
                record->ExceptionInformation[0] = kMsvcEhMagic;
            }
            break;
        }
    }
    ::ReleaseSRWLockShared(&state.lock);
    return EXCEPTION_CONTINUE_SEARCH;
}

void registerExceptionRouting(ModuleState& state) {
    auto& exceptionRouter = router();
    DWORD registrationError{};
    bool capacityExceeded = false;
    ::AcquireSRWLockExclusive(&exceptionRouter.lock);
    if (exceptionRouter.handler == nullptr) {
        exceptionRouter.handler = ::AddVectoredExceptionHandler(1, routeMsvcException);
        if (exceptionRouter.handler == nullptr) registrationError = ::GetLastError();
    }
    if (registrationError == 0 && exceptionRouter.imageCount == exceptionRouter.images.size()) {
        capacityExceeded = true;
    } else if (registrationError == 0) {
        const auto begin = reinterpret_cast<std::uintptr_t>(state.base);
        exceptionRouter.images[exceptionRouter.imageCount++] = {begin, begin + state.size};
        state.exceptionRoutingRegistered = true;
    }
    ::ReleaseSRWLockExclusive(&exceptionRouter.lock);
    if (registrationError != 0) {
        fail(PeErrorCode::ExceptionRegistrationFailed,
            "AddVectoredExceptionHandler failed for MSVC exception routing", registrationError);
    }
    if (capacityExceeded) {
        fail(PeErrorCode::ExceptionRegistrationFailed,
            "The process already has the maximum number of manually mapped unwind images");
    }
}

void unregisterExceptionRouting(ModuleState& state) noexcept {
    if (!state.exceptionRoutingRegistered) return;
    auto& exceptionRouter = router();
    ::AcquireSRWLockExclusive(&exceptionRouter.lock);
    const auto begin = reinterpret_cast<std::uintptr_t>(state.base);
    for (std::size_t index = 0; index < exceptionRouter.imageCount; ++index) {
        if (exceptionRouter.images[index].begin == begin) {
            exceptionRouter.images[index] = exceptionRouter.images[exceptionRouter.imageCount - 1];
            --exceptionRouter.imageCount;
            break;
        }
    }
    if (exceptionRouter.imageCount == 0 && exceptionRouter.handler != nullptr) {
        ::RemoveVectoredExceptionHandler(exceptionRouter.handler);
        exceptionRouter.handler = nullptr;
    }
    state.exceptionRoutingRegistered = false;
    ::ReleaseSRWLockExclusive(&exceptionRouter.lock);
}

} // namespace

void registerExceptions(ModuleState& state) {
    const auto exceptionDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (exceptionDirectory.VirtualAddress == 0 || exceptionDirectory.Size == 0) {
        return;
    }
    if (exceptionDirectory.Size % sizeof(RUNTIME_FUNCTION) != 0) {
        fail(PeErrorCode::InvalidExceptionDirectory,
            "Exception directory size is not a multiple of RUNTIME_FUNCTION");
    }
    const std::size_t count = exceptionDirectory.Size / sizeof(RUNTIME_FUNCTION);
    if (count > MAXDWORD) {
        fail(PeErrorCode::InvalidExceptionDirectory, "Exception directory contains too many functions");
    }
    auto tableBytes = mappedSpan(
        state, exceptionDirectory.VirtualAddress, exceptionDirectory.Size,
        PeErrorCode::InvalidExceptionDirectory, "Exception directory");
    auto* table = reinterpret_cast<RUNTIME_FUNCTION*>(tableBytes.data());
    for (std::size_t i = 0; i < count; ++i) {
        const auto& entry = table[i];
        if (entry.BeginAddress >= entry.EndAddress || entry.EndAddress > state.size ||
            entry.UnwindData >= state.size) {
            fail(PeErrorCode::InvalidExceptionDirectory, "A runtime-function entry contains an invalid RVA");
        }
    }
    void* dynamicTable{};
    const auto base = reinterpret_cast<ULONG_PTR>(state.base);
    const DWORD status = ::RtlAddGrowableFunctionTable(
        &dynamicTable,
        table,
        static_cast<DWORD>(count),
        static_cast<DWORD>(count),
        base,
        base + state.size);
    if (status != 0) {
        fail(PeErrorCode::ExceptionRegistrationFailed,
            "RtlAddGrowableFunctionTable rejected the exception directory", status);
    }
    state.exceptionTable = table;
    state.exceptionCount = static_cast<DWORD>(count);
    state.growableFunctionTable = dynamicTable;
    state.exceptionRegistered = true;
    try {
        registerExceptionRouting(state);
    } catch (...) {
        ::RtlDeleteGrowableFunctionTable(dynamicTable);
        state.growableFunctionTable = nullptr;
        state.exceptionTable = nullptr;
        state.exceptionCount = 0;
        state.exceptionRegistered = false;
        throw;
    }
    std::ostringstream message;
    message << "registered " << count << " growable runtime functions at " << table
            << " for base " << static_cast<void*>(state.base);
    log(message.str());
}

void unregisterExceptions(ModuleState& state) noexcept {
    unregisterExceptionRouting(state);
    if (state.exceptionRegistered && state.growableFunctionTable != nullptr) {
        ::RtlDeleteGrowableFunctionTable(state.growableFunctionTable);
        state.exceptionRegistered = false;
        state.exceptionTable = nullptr;
        state.exceptionCount = 0;
        state.growableFunctionTable = nullptr;
    }
}

} // namespace pe::detail
