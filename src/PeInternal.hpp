#pragma once

#include "pe_loader/PeError.hpp"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pe::detail {

constexpr std::size_t kMaximumImageSize = 2ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumSections = 96;

struct ParsedImage {
    std::span<const std::byte> file;
    IMAGE_NT_HEADERS64 nt{};
    std::vector<IMAGE_SECTION_HEADER> sections;
};

[[noreturn]] void fail(PeErrorCode code, std::string message, DWORD systemError = 0);
[[nodiscard]] ParsedImage parseImage(std::span<const std::byte> image);

[[nodiscard]] bool checkedRange(std::size_t offset, std::size_t length, std::size_t total) noexcept;
[[nodiscard]] std::span<const std::byte> fileSpan(
    const ParsedImage& image, std::size_t offset, std::size_t length, PeErrorCode code, std::string_view context);

} // namespace pe::detail
