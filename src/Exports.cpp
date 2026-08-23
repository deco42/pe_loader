#include "PeInternal.hpp"

#include <cstring>
#include <limits>

namespace pe::detail {
namespace {

template <typename T>
T readMapped(const ModuleState& state, std::uint32_t rva, PeErrorCode code, std::string_view context) {
    auto bytes = mappedSpan(state, rva, sizeof(T), code, context);
    T value{};
    std::memcpy(&value, bytes.data(), sizeof(value));
    return value;
}

std::uint32_t addRva(std::uint32_t base, std::size_t offset, PeErrorCode code) {
    if (offset > UINT32_MAX || base > UINT32_MAX - offset) {
        fail(code, "Export-table RVA arithmetic overflow");
    }
    return static_cast<std::uint32_t>(base + offset);
}

void* resolveFunctionRva(ModuleState& state, std::uint32_t functionRva, IMAGE_DATA_DIRECTORY exportDirectory) {
    if (functionRva == 0) {
        fail(PeErrorCode::ExportNotFound, "The export is a null RVA");
    }
    (void)mappedSpan(state, functionRva, 1, PeErrorCode::InvalidExportDirectory, "Export target");
    return state.base + functionRva;
}

} // namespace

void* resolveExport(ModuleState& state, const char* name) {
    if (name == nullptr || *name == '\0') {
        fail(PeErrorCode::InvalidArgument, "Export name must not be null or empty");
    }
    const auto exportDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        fail(PeErrorCode::ExportNotFound, "The DLL has no export directory");
    }
    const auto* exports = mappedObject<IMAGE_EXPORT_DIRECTORY>(
        state, exportDirectory.VirtualAddress, PeErrorCode::InvalidExportDirectory, "Export directory");
    for (std::size_t i = 0; i < exports->NumberOfNames; ++i) {
        const DWORD nameRva = readMapped<DWORD>(state,
            addRva(exports->AddressOfNames, i * sizeof(DWORD), PeErrorCode::InvalidExportDirectory),
            PeErrorCode::InvalidExportDirectory, "Export name RVA");
        if (mappedString(state, nameRva, PeErrorCode::InvalidExportDirectory, "Export name") != name) continue;
        const WORD index = readMapped<WORD>(state,
            addRva(exports->AddressOfNameOrdinals, i * sizeof(WORD), PeErrorCode::InvalidExportDirectory),
            PeErrorCode::InvalidExportDirectory, "Export ordinal index");
        if (index >= exports->NumberOfFunctions) {
            fail(PeErrorCode::InvalidExportDirectory, "Export ordinal index exceeds the address table");
        }
        const DWORD functionRva = readMapped<DWORD>(state,
            addRva(exports->AddressOfFunctions, static_cast<std::size_t>(index) * sizeof(DWORD),
                PeErrorCode::InvalidExportDirectory),
            PeErrorCode::InvalidExportDirectory, "Export function RVA");
        return resolveFunctionRva(state, functionRva, exportDirectory);
    }
    fail(PeErrorCode::ExportNotFound, "Export was not found: " + std::string(name));
}

void* resolveExport(ModuleState& state, std::uint16_t ordinal) {
    const auto exportDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        fail(PeErrorCode::ExportNotFound, "The DLL has no export directory");
    }
    const auto* exports = mappedObject<IMAGE_EXPORT_DIRECTORY>(
        state, exportDirectory.VirtualAddress, PeErrorCode::InvalidExportDirectory, "Export directory");
    if (ordinal < exports->Base) {
        fail(PeErrorCode::ExportNotFound, "Export ordinal is below the directory base");
    }
    const DWORD index = ordinal - exports->Base;
    if (index >= exports->NumberOfFunctions) {
        fail(PeErrorCode::ExportNotFound, "Export ordinal exceeds the address table");
    }
    const DWORD functionRva = readMapped<DWORD>(state,
        addRva(exports->AddressOfFunctions, static_cast<std::size_t>(index) * sizeof(DWORD),
            PeErrorCode::InvalidExportDirectory),
        PeErrorCode::InvalidExportDirectory, "Export function RVA");
    return resolveFunctionRva(state, functionRva, exportDirectory);
}

} // namespace pe::detail
