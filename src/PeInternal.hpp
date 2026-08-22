#pragma once

#include "pe_loader/PeError.hpp"
#include "pe_loader/PeImage.hpp"

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

struct ModuleState {
    std::byte* base{};
    std::size_t size{};
    std::uint64_t preferredBase{};
    std::uint32_t entryPointRva{};
    std::vector<IMAGE_SECTION_HEADER> sections;
};

[[noreturn]] void fail(PeErrorCode code, std::string message, DWORD systemError = 0);
[[nodiscard]] ParsedImage parseImage(std::span<const std::byte> image);
[[nodiscard]] ImageInfo toImageInfo(const ParsedImage& image);

[[nodiscard]] bool checkedRange(std::size_t offset, std::size_t length, std::size_t total) noexcept;
[[nodiscard]] std::span<const std::byte> fileSpan(
    const ParsedImage& image, std::size_t offset, std::size_t length, PeErrorCode code, std::string_view context);
[[nodiscard]] std::span<std::byte> mappedSpan(
    ModuleState& state, std::uint32_t rva, std::size_t length, PeErrorCode code, std::string_view context);
[[nodiscard]] std::span<const std::byte> mappedSpan(
    const ModuleState& state, std::uint32_t rva, std::size_t length, PeErrorCode code, std::string_view context);
[[nodiscard]] std::string mappedString(
    const ModuleState& state, std::uint32_t rva, PeErrorCode code, std::string_view context);

template <typename T>
[[nodiscard]] T* mappedObject(
    ModuleState& state, std::uint32_t rva, PeErrorCode code, std::string_view context) {
    auto bytes = mappedSpan(state, rva, sizeof(T), code, context);
    return reinterpret_cast<T*>(bytes.data());
}

template <typename T>
[[nodiscard]] const T* mappedObject(
    const ModuleState& state, std::uint32_t rva, PeErrorCode code, std::string_view context) {
    auto bytes = mappedSpan(state, rva, sizeof(T), code, context);
    return reinterpret_cast<const T*>(bytes.data());
}

[[nodiscard]] const IMAGE_NT_HEADERS64& mappedNt(const ModuleState& state);
[[nodiscard]] IMAGE_NT_HEADERS64& mappedNt(ModuleState& state);
[[nodiscard]] IMAGE_DATA_DIRECTORY directory(const ModuleState& state, std::size_t index);

void allocateAndMap(const ParsedImage& image, ModuleState& state);
void applyRelocations(ModuleState& state);

void log(std::string_view message) noexcept;

} // namespace pe::detail
