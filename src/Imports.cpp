#include "PeInternal.hpp"

#include <cstring>
#include <sstream>

namespace pe::detail {
namespace {

void resolveThunkTable(
    ModuleState& state,
    HMODULE module,
    const std::string& moduleName,
    std::uint32_t lookupRva,
    std::uint32_t iatRva,
    PeErrorCode invalidCode) {
    for (std::size_t index = 0;; ++index) {
        if (index > state.size / sizeof(IMAGE_THUNK_DATA64)) {
            fail(invalidCode, "Import thunk table is not terminated");
        }
        const std::size_t byteOffset = index * sizeof(IMAGE_THUNK_DATA64);
        if (lookupRva > UINT32_MAX - byteOffset || iatRva > UINT32_MAX - byteOffset) {
            fail(invalidCode, "Import thunk RVA overflows");
        }
        const auto* lookup = mappedObject<IMAGE_THUNK_DATA64>(
            state, static_cast<std::uint32_t>(lookupRva + byteOffset), invalidCode, "Import lookup thunk");
        auto* iat = mappedObject<IMAGE_THUNK_DATA64>(
            state, static_cast<std::uint32_t>(iatRva + byteOffset), invalidCode, "Import address thunk");
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
            if (value > UINT32_MAX) {
                fail(invalidCode, "Import-by-name RVA exceeds 32 bits");
            }
            const auto* importName = mappedObject<IMAGE_IMPORT_BY_NAME>(
                state, static_cast<std::uint32_t>(value), invalidCode, "Import-by-name record");
            (void)importName;
            if (value > UINT32_MAX - offsetof(IMAGE_IMPORT_BY_NAME, Name)) {
                fail(invalidCode, "Import name RVA overflows");
            }
            symbol = mappedString(
                state, static_cast<std::uint32_t>(value + offsetof(IMAGE_IMPORT_BY_NAME, Name)),
                invalidCode, "Imported symbol name");
            address = ::GetProcAddress(module, symbol.c_str());
        }
        if (address == nullptr) {
            fail(PeErrorCode::ImportSymbolNotFound,
                "Import resolution failed: " + moduleName + "!" + symbol, ::GetLastError());
        }
        iat->u1.Function = reinterpret_cast<ULONGLONG>(address);
    }
}

} // namespace

void resolveImports(ModuleState& state) {
    const auto importDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0) {
        return;
    }
    auto bytes = mappedSpan(
        state, importDirectory.VirtualAddress, importDirectory.Size,
        PeErrorCode::InvalidImportDirectory, "Import directory");
    bool terminated = false;
    for (std::size_t cursor = 0; checkedRange(cursor, sizeof(IMAGE_IMPORT_DESCRIPTOR), bytes.size());
        cursor += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        std::memcpy(&descriptor, bytes.data() + cursor, sizeof(descriptor));
        if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 && descriptor.Name == 0) {
            terminated = true;
            break;
        }
        if (descriptor.Name == 0 || descriptor.FirstThunk == 0) {
            fail(PeErrorCode::InvalidImportDirectory, "Import descriptor is missing a name or IAT");
        }
        const std::string moduleName = mappedString(
            state, descriptor.Name, PeErrorCode::InvalidImportDirectory, "Imported module name");
        HMODULE module = ::LoadLibraryA(moduleName.c_str());
        if (module == nullptr) {
            fail(PeErrorCode::ImportModuleNotFound,
                "Import module could not be loaded: " + moduleName, ::GetLastError());
        }
        state.dependencies.push_back({moduleName, module});
        const std::uint32_t lookupRva = descriptor.OriginalFirstThunk != 0
            ? descriptor.OriginalFirstThunk
            : descriptor.FirstThunk;
        resolveThunkTable(
            state, module, moduleName, lookupRva, descriptor.FirstThunk,
            PeErrorCode::InvalidImportDirectory);
    }
    if (!terminated) {
        fail(PeErrorCode::InvalidImportDirectory, "Import descriptor list is not terminated inside its directory");
    }
}

} // namespace pe::detail
