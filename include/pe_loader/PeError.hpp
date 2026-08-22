#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace pe {

enum class PeErrorCode {
    InvalidArgument,
    InvalidDosHeader,
    InvalidNtHeader,
    UnsupportedArchitecture,
    UnsupportedImageType,
    InvalidOptionalHeader,
    ImageTooLarge,
    InvalidSection,
    InvalidDataDirectory,
    AllocationFailed,
    RelocationRequiredButUnavailable,
    InvalidRelocationDirectory,
    UnsupportedRelocation,
    ImportModuleNotFound,
    ImportSymbolNotFound,
    InvalidImportDirectory
};

class PeError final : public std::runtime_error {
public:
    PeError(PeErrorCode code, std::string message, unsigned long systemError = 0)
        : std::runtime_error(std::move(message)), code_(code), systemError_(systemError) {}

    [[nodiscard]] PeErrorCode code() const noexcept { return code_; }
    [[nodiscard]] unsigned long systemError() const noexcept { return systemError_; }

private:
    PeErrorCode code_;
    unsigned long systemError_;
};

} // namespace pe
