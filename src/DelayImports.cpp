#include "PeInternal.hpp"

#include <delayimp.h>
#include <cstring>

namespace pe::detail {
namespace {

std::uint32_t delayFieldToRva(const ModuleState& state, DWORD value, bool fieldsAreRvas) {
    if (fieldsAreRvas) {
        return value;
    }
    const auto absolute = static_cast<std::uint64_t>(value);
    const auto base = reinterpret_cast<std::uint64_t>(state.base);
    if (absolute < base || absolute - base > UINT32_MAX) {
        fail(PeErrorCode::InvalidDelayImportDirectory, "A delay-import VA is outside the mapped image");
    }
    return static_cast<std::uint32_t>(absolute - base);
}

} // namespace

void resolveDelayImports(ModuleState& state) {
    const auto delayDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    if (delayDirectory.VirtualAddress == 0 || delayDirectory.Size == 0) {
        return;
    }
    auto bytes = mappedSpan(
        state, delayDirectory.VirtualAddress, delayDirectory.Size,
        PeErrorCode::InvalidDelayImportDirectory, "Delay-import directory");
    bool terminated = false;
    for (std::size_t cursor = 0; checkedRange(cursor, sizeof(ImgDelayDescr), bytes.size());
        cursor += sizeof(ImgDelayDescr)) {
        ImgDelayDescr descriptor{};
        std::memcpy(&descriptor, bytes.data() + cursor, sizeof(descriptor));
        if (descriptor.rvaDLLName == 0 && descriptor.rvaIAT == 0 && descriptor.rvaINT == 0) {
            terminated = true;
            break;
        }
        const bool rvaFields = (descriptor.grAttrs & dlattrRva) != 0;
        if ((descriptor.grAttrs & ~dlattrRva) != 0) {
            fail(PeErrorCode::InvalidDelayImportDirectory, "Delay-import descriptor has unknown attributes");
        }
        const auto nameRva = delayFieldToRva(state, descriptor.rvaDLLName, rvaFields);
        const auto iatRva = delayFieldToRva(state, descriptor.rvaIAT, rvaFields);
        const auto intRva = delayFieldToRva(state, descriptor.rvaINT, rvaFields);
        if (nameRva == 0 || iatRva == 0 || intRva == 0) {
            fail(PeErrorCode::InvalidDelayImportDirectory, "Delay-import descriptor is incomplete");
        }
        const std::string moduleName = mappedString(
            state, nameRva, PeErrorCode::InvalidDelayImportDirectory, "Delay-import module name");
        HMODULE module = ::LoadLibraryA(moduleName.c_str());
        if (module == nullptr) {
            fail(PeErrorCode::ImportModuleNotFound,
                "Delay-import module could not be loaded: " + moduleName, ::GetLastError());
        }
        state.dependencies.push_back({moduleName, module});

        if (descriptor.rvaHmod != 0) {
            const auto hmodRva = delayFieldToRva(state, descriptor.rvaHmod, rvaFields);
            auto target = mappedSpan(
                state, hmodRva, sizeof(HMODULE), PeErrorCode::InvalidDelayImportDirectory,
                "Delay-import module handle slot");
            std::memcpy(target.data(), &module, sizeof(module));
        }

        for (std::size_t index = 0;; ++index) {
            const std::size_t offset = index * sizeof(IMAGE_THUNK_DATA64);
            if (index > state.size / sizeof(IMAGE_THUNK_DATA64) ||
                intRva > UINT32_MAX - offset || iatRva > UINT32_MAX - offset) {
                fail(PeErrorCode::InvalidDelayImportDirectory, "Delay-import thunk table is not terminated");
            }
            const auto* lookup = mappedObject<IMAGE_THUNK_DATA64>(
                state, static_cast<std::uint32_t>(intRva + offset),
                PeErrorCode::InvalidDelayImportDirectory, "Delay-import lookup thunk");
            auto* iat = mappedObject<IMAGE_THUNK_DATA64>(
                state, static_cast<std::uint32_t>(iatRva + offset),
                PeErrorCode::InvalidDelayImportDirectory, "Delay-import address thunk");
            const ULONGLONG value = lookup->u1.AddressOfData;
            if (value == 0) {
                break;
            }
            FARPROC address{};
            std::string symbol;
            if (IMAGE_SNAP_BY_ORDINAL64(value)) {
                const WORD ordinal = IMAGE_ORDINAL64(value);
                symbol = "#" + std::to_string(ordinal);
                address = ::GetProcAddress(module, MAKEINTRESOURCEA(ordinal));
            } else {
                if (value > UINT32_MAX - offsetof(IMAGE_IMPORT_BY_NAME, Name)) {
                    fail(PeErrorCode::InvalidDelayImportDirectory, "Delay-import name RVA overflows");
                }
                symbol = mappedString(
                    state, static_cast<std::uint32_t>(value + offsetof(IMAGE_IMPORT_BY_NAME, Name)),
                    PeErrorCode::InvalidDelayImportDirectory, "Delay-import symbol name");
                address = ::GetProcAddress(module, symbol.c_str());
            }
            if (address == nullptr) {
                fail(PeErrorCode::ImportSymbolNotFound,
                    "Delay-import resolution failed: " + moduleName + "!" + symbol, ::GetLastError());
            }
            iat->u1.Function = reinterpret_cast<ULONGLONG>(address);
        }
    }
    if (!terminated) {
        fail(PeErrorCode::InvalidDelayImportDirectory,
            "Delay-import descriptor list is not terminated inside its directory");
    }
}

} // namespace pe::detail
