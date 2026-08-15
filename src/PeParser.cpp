#include "PeInternal.hpp"

#include <cstring>
#include <limits>
#include <sstream>

namespace pe::detail {
namespace {

template <typename T>
T readObject(std::span<const std::byte> bytes, std::size_t offset, PeErrorCode code, std::string_view context) {
    if (!checkedRange(offset, sizeof(T), bytes.size())) {
        fail(code, std::string(context) + " is truncated");
    }
    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

} // namespace

[[noreturn]] void fail(PeErrorCode code, std::string message, DWORD systemError) {
    throw PeError(code, std::move(message), systemError);
}

bool checkedRange(std::size_t offset, std::size_t length, std::size_t total) noexcept {
    return offset + length <= total;
}

std::span<const std::byte> fileSpan(
    const ParsedImage& image,
    std::size_t offset,
    std::size_t length,
    PeErrorCode code,
    std::string_view context) {
    if (!checkedRange(offset, length, image.file.size())) {
        fail(code, std::string(context) + " is outside the input buffer");
    }
    return image.file.subspan(offset, length);
}

ParsedImage parseImage(std::span<const std::byte> image) {
    if (image.data() == nullptr || image.empty()) {
        fail(PeErrorCode::InvalidArgument, "The PE image buffer is empty");
    }

    const auto dos = readObject<IMAGE_DOS_HEADER>(image, 0, PeErrorCode::InvalidDosHeader, "DOS header");
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fail(PeErrorCode::InvalidDosHeader, "Invalid DOS signature (expeced MZ)");
    }
    if (dos.e_lfanew < 0) {
        fail(PeErrorCode::InvalidNtHeader, "DOS e_lfanew is negative");
    }

    const std::size_t ntOffset = static_cast<std::size_t>(dos.e_lfanew);
    const auto signature = readObject<DWORD>(image, ntOffset, PeErrorCode::InvalidNtHeader, "PE signature");
    if (signature != IMAGE_NT_SIGNATURE) {
        fail(PeErrorCode::InvalidNtHeader, "Invalid PE signature");
    }

    const std::size_t fileHeaderOffset = ntOffset + sizeof(DWORD);
    const auto fileHeader = readObject<IMAGE_FILE_HEADER>(
        image, fileHeaderOffset, PeErrorCode::InvalidNtHeader, "COFF file header");
    if (fileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        fail(PeErrorCode::UnsupportedArchitecture, "Only IMAGE_FILE_MACHINE_AMD64 is supported");
    }
    if ((fileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
        fail(PeErrorCode::UnsupportedImageType, "Only DLL images are supported");
    }
    if (fileHeader.NumberOfSections == 0 || fileHeader.NumberOfSections > kMaximumSections) {
        fail(PeErrorCode::InvalidSection, "The section count is zero or exceedes the safety limit");
    }

    const std::size_t optionalOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        fail(PeErrorCode::InvalidOptionalHeader, "PE32+ optional header is too small");
    }
    (void)fileSpan(ParsedImage{image}, optionalOffset, fileHeader.SizeOfOptionalHeader,
        PeErrorCode::InvalidOptionalHeader, "Optional header");
    const auto optional = readObject<IMAGE_OPTIONAL_HEADER64>(
        image, optionalOffset, PeErrorCode::InvalidOptionalHeader, "PE32+ optional header");
    if (optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fail(PeErrorCode::UnsupportedArchitecture, "Only PE32+ optional headers are supported");
    }
    if (optional.SizeOfImage == 0 || optional.SizeOfImage > kMaximumImageSize) {
        fail(PeErrorCode::ImageTooLarge, "SizeOfImage is zero or exceeds 2 GiB");
    }
    if (optional.SizeOfHeaders == 0 || optional.SizeOfHeaders > optional.SizeOfImage ||
        optional.SizeOfHeaders > image.size()) {
        fail(PeErrorCode::InvalidOptionalHeader, "SizeOfHeaders is outside the file or image");
    }
    const std::size_t sectionOffset = optionalOffset + fileHeader.SizeOfOptionalHeader;
    const std::size_t sectionBytes = static_cast<std::size_t>(fileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (!checkedRange(sectionOffset, sectionBytes, image.size()) || sectionOffset + sectionBytes > optional.SizeOfHeaders) {
        fail(PeErrorCode::InvalidSection, "Section table is truncated or lies beyond SizeOfHeaders");
    }

    ParsedImage result;
    result.file = image;
    result.nt.Signature = signature;
    result.nt.FileHeader = fileHeader;
    result.nt.OptionalHeader = optional;
    result.sections.reserve(fileHeader.NumberOfSections);

    for (std::size_t i = 0; i < fileHeader.NumberOfSections; ++i) {
        const auto section = readObject<IMAGE_SECTION_HEADER>(
            image, sectionOffset + i * sizeof(IMAGE_SECTION_HEADER), PeErrorCode::InvalidSection, "Section header");
        const std::uint64_t mappedSize = std::max<std::uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (mappedSize != 0 &&
            (section.VirtualAddress >= optional.SizeOfImage || mappedSize > optional.SizeOfImage - section.VirtualAddress)) {
            fail(PeErrorCode::InvalidSection, "Section virtual range exceeds SizeOfImage");
        }
        if (section.SizeOfRawData != 0 &&
            !checkedRange(section.PointerToRawData, section.SizeOfRawData, image.size())) {
            fail(PeErrorCode::InvalidSection, "Section raw range exceeds the input buffer");
        }
        result.sections.push_back(section);
    }

    return result;
}

} // namespace pe::detail
