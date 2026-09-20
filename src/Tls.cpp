#include "PeInternal.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>

namespace pe::detail {
namespace {

std::uint32_t vaToRva(
    const ModuleState& state, ULONGLONG address, std::size_t length, std::string_view context) {
    if (address == 0) return 0;
    const auto base = reinterpret_cast<std::uint64_t>(state.base);
    if (address < base || address - base > UINT32_MAX ||
        !checkedRange(static_cast<std::size_t>(address - base), length, state.size)) {
        fail(PeErrorCode::InvalidTlsDirectory, std::string(context) + " is outside the mapped image");
    }
    return static_cast<std::uint32_t>(address - base);
}

[[nodiscard]] std::size_t tlsAlignment(DWORD characteristics) {
    const DWORD encoding = (characteristics & 0x00F00000) >> 20;
    if (encoding == 0) return 1;
    if (encoding >= 14) {
        fail(PeErrorCode::InvalidTlsDirectory, "TLS Characteristics has an invalid alignment encoding");
    }
    return std::size_t{1} << (encoding - 1);
}

void invokeTlsCallbacks(ModuleState& state, DWORD reason) noexcept {
    for (const auto callback : state.tlsCallbacks) {
        callback(reinterpret_cast<PVOID>(state.base), reason, nullptr);
    }
}

} // namespace

void collectTlsCallbacks(ModuleState& state) {
    const auto tlsDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_TLS);
    if (tlsDirectory.VirtualAddress == 0 || tlsDirectory.Size == 0) return;
    if (tlsDirectory.Size < sizeof(IMAGE_TLS_DIRECTORY64)) {
        fail(PeErrorCode::InvalidTlsDirectory, "TLS directory is smaller than IMAGE_TLS_DIRECTORY64");
    }
    const auto tlsBytes = mappedSpan(state, tlsDirectory.VirtualAddress, sizeof(IMAGE_TLS_DIRECTORY64),
        PeErrorCode::InvalidTlsDirectory, "TLS directory");
    IMAGE_TLS_DIRECTORY64 tlsValue{};
    std::memcpy(&tlsValue, tlsBytes.data(), sizeof(tlsValue));
    const auto* tls = &tlsValue;

    auto& staticTls = state.staticTls;
    staticTls.directoryPresent = true;
    staticTls.directoryRva = tlsDirectory.VirtualAddress;
    staticTls.alignment = tlsAlignment(tls->Characteristics);

    if (tls->EndAddressOfRawData < tls->StartAddressOfRawData) {
        fail(PeErrorCode::InvalidTlsDirectory, "TLS raw-data range is reversed");
    }
    const std::uint64_t rawLength = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
    if (rawLength > SIZE_MAX) {
        fail(PeErrorCode::InvalidTlsDirectory, "TLS template is too large");
    }
    const auto rawSize = static_cast<std::size_t>(rawLength);
    const auto zeroFillSize = static_cast<std::size_t>(tls->SizeOfZeroFill);
    if (rawSize > (std::numeric_limits<std::size_t>::max)() - zeroFillSize) {
        fail(PeErrorCode::InvalidTlsDirectory, "TLS total block size overflows");
    }
    const auto totalBlockSize = rawSize + zeroFillSize;
    if (totalBlockSize > kMaximumImageSize) {
        fail(PeErrorCode::InvalidTlsDirectory, "TLS total block exceeds the loader safety limit");
    }
    staticTls.compilerManaged = totalBlockSize != 0;
    staticTls.rawTemplateSize = rawSize;
    staticTls.zeroFillSize = zeroFillSize;
    staticTls.totalBlockSize = totalBlockSize;

    if (rawSize != 0) {
        const auto templateRva = vaToRva(state, tls->StartAddressOfRawData, rawSize, "TLS template");
        const auto templateBytes = mappedSpan(
            state, templateRva, rawSize, PeErrorCode::InvalidTlsDirectory, "TLS template");
        staticTls.templateBytes.assign(templateBytes.begin(), templateBytes.end());
    } else if (tls->StartAddressOfRawData != 0) {
        // A callback-only image may use equal non-null start/end markers. They
        // are still PE32+ VAs and must not point outside the mapped image.
        (void)vaToRva(state, tls->StartAddressOfRawData, 0, "empty TLS template marker");
    }

    if (tls->AddressOfIndex != 0) {
        staticTls.indexRva = vaToRva(state, tls->AddressOfIndex, sizeof(DWORD), "TLS index slot");
    } else if (staticTls.compilerManaged) {
        fail(PeErrorCode::InvalidTlsDirectory, "Compiler-managed TLS has no AddressOfIndex");
    }

    if (tls->AddressOfCallBacks != 0) {
        const auto callbacksRva = vaToRva(
            state, tls->AddressOfCallBacks, sizeof(PIMAGE_TLS_CALLBACK), "TLS callback array");
        for (std::size_t index = 0;; ++index) {
            if (index > state.size / sizeof(PIMAGE_TLS_CALLBACK)) {
                fail(PeErrorCode::InvalidTlsDirectory, "TLS callback array is not terminated");
            }
            const std::size_t offset = index * sizeof(PIMAGE_TLS_CALLBACK);
            if (callbacksRva > UINT32_MAX - offset) {
                fail(PeErrorCode::InvalidTlsDirectory, "TLS callback array RVA overflows");
            }
            auto slot = mappedSpan(
                state, static_cast<std::uint32_t>(callbacksRva + offset), sizeof(PIMAGE_TLS_CALLBACK),
                PeErrorCode::InvalidTlsDirectory, "TLS callback slot");
            PIMAGE_TLS_CALLBACK callback{};
            std::memcpy(&callback, slot.data(), sizeof(callback));
            if (callback == nullptr) break;
            (void)vaToRva(state, reinterpret_cast<std::uint64_t>(callback), 1, "TLS callback");
            state.tlsCallbacks.push_back(callback);
        }
    }

    std::ostringstream diagnostics;
    diagnostics << "[TLS] directory present raw template size=" << staticTls.rawTemplateSize
                << " zero fill=" << staticTls.zeroFillSize
                << " alignment=" << staticTls.alignment
                << " index storage RVA=0x" << std::hex << staticTls.indexRva
                << " callbacks=" << std::dec << state.tlsCallbacks.size();
    log(diagnostics.str());

    if (staticTls.compilerManaged) {
        fail(PeErrorCode::StaticTlsUnsupported,
            "The DLL contains static TLS. TlsAlloc/TlsSetValue do not populate the loader-managed static TLS vector used by MSVC-generated code");
    }
}

void runTlsCallbacks(ModuleState& state, DWORD reason) noexcept {
    if (reason == DLL_PROCESS_ATTACH) {
        invokeTlsCallbacks(state, reason);
        state.callbacksAttached = !state.tlsCallbacks.empty();
        return;
    }
    if (!state.callbacksAttached) return;
    invokeTlsCallbacks(state, reason);
    state.callbacksAttached = false;
}

} // namespace pe::detail
