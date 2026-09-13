#include "PeInternal.hpp"

#include <algorithm>
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

bool isPowerOfTwo(std::uint32_t value) noexcept {
    return value != 0 && (value & (value - 1)) == 0;
}

bool hasDirectory(const ParsedImage& image, std::size_t index) noexcept {
    return image.nt.OptionalHeader.NumberOfRvaAndSizes > index &&
        image.nt.OptionalHeader.DataDirectory[index].VirtualAddress != 0 &&
        image.nt.OptionalHeader.DataDirectory[index].Size != 0;
}

} // namespace

[[noreturn]] void fail(PeErrorCode code, std::string message, DWORD systemError) {
    throw PeError(code, std::move(message), systemError);
}

bool checkedRange(std::size_t offset, std::size_t length, std::size_t total) noexcept {
    return offset <= total && length <= total - offset;
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

std::span<std::byte> mappedSpan(
    ModuleState& state,
    std::uint32_t rva,
    std::size_t length,
    PeErrorCode code,
    std::string_view context) {
    if (state.base == nullptr || !checkedRange(rva, length, state.size)) {
        fail(code, std::string(context) + " is outside the mapped image");
    }
    return {state.base + rva, length};
}

std::span<const std::byte> mappedSpan(
    const ModuleState& state,
    std::uint32_t rva,
    std::size_t length,
    PeErrorCode code,
    std::string_view context) {
    if (state.base == nullptr || !checkedRange(rva, length, state.size)) {
        fail(code, std::string(context) + " is outside the mapped image");
    }
    return {state.base + rva, length};
}

std::string mappedString(
    const ModuleState& state,
    std::uint32_t rva,
    PeErrorCode code,
    std::string_view context) {
    if (state.base == nullptr || rva >= state.size) {
        fail(code, std::string(context) + " starts outside the mapped image");
    }
    const char* begin = reinterpret_cast<const char*>(state.base + rva);
    const std::size_t remaining = state.size - rva;
    const void* terminator = std::memchr(begin, '\0', remaining);
    if (terminator == nullptr) {
        fail(code, std::string(context) + " is not null terminated inside the mapped image");
    }
    return std::string(begin, static_cast<const char*>(terminator));
}

ParsedImage parseImage(std::span<const std::byte> image) {
    if (image.data() == nullptr || image.empty()) {
        fail(PeErrorCode::InvalidArgument, "The PE image buffer is empty");
    }

    const auto dos = readObject<IMAGE_DOS_HEADER>(image, 0, PeErrorCode::InvalidDosHeader, "DOS header");
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fail(PeErrorCode::InvalidDosHeader, "Invalid DOS signature (expected MZ)");
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
        fail(PeErrorCode::InvalidSection, "The section count is zero or exceeds the safety limit");
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
    if (optional.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        fail(PeErrorCode::InvalidOptionalHeader, "NumberOfRvaAndSizes exceeds the supported PE directory count");
    }
    if (optional.SizeOfImage == 0 || optional.SizeOfImage > kMaximumImageSize) {
        fail(PeErrorCode::ImageTooLarge, "SizeOfImage is zero or exceeds 2 GiB");
    }
    if (optional.SizeOfHeaders == 0 || optional.SizeOfHeaders > optional.SizeOfImage ||
        optional.SizeOfHeaders > image.size()) {
        fail(PeErrorCode::InvalidOptionalHeader, "SizeOfHeaders is outside the file or image");
    }
    if (!isPowerOfTwo(optional.FileAlignment) || !isPowerOfTwo(optional.SectionAlignment) ||
        optional.FileAlignment > 65536 ||
        (optional.SectionAlignment < 4096 && optional.SectionAlignment != optional.FileAlignment) ||
        (optional.SectionAlignment >= 4096 && optional.FileAlignment < 512) ||
        optional.SectionAlignment < optional.FileAlignment) {
        fail(PeErrorCode::InvalidOptionalHeader, "Invalid SectionAlignment/FileAlignment combination");
    }
    if (optional.AddressOfEntryPoint != 0 && optional.AddressOfEntryPoint >= optional.SizeOfImage) {
        fail(PeErrorCode::InvalidOptionalHeader, "AddressOfEntryPoint is outside the image");
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

    for (std::size_t i = 0; i < optional.NumberOfRvaAndSizes; ++i) {
        const auto& dir = optional.DataDirectory[i];
        if (dir.VirtualAddress == 0 && dir.Size == 0) {
            continue;
        }
        if (dir.VirtualAddress == 0 || dir.Size == 0) {
            fail(PeErrorCode::InvalidDataDirectory, "A data directory has only one of RVA/Size set");
        }
        if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
            if (!checkedRange(dir.VirtualAddress, dir.Size, image.size())) {
                fail(PeErrorCode::InvalidDataDirectory, "Certificate table exceeds the input file");
            }
        } else if (dir.VirtualAddress >= optional.SizeOfImage || dir.Size > optional.SizeOfImage - dir.VirtualAddress) {
            fail(PeErrorCode::InvalidDataDirectory, "A data directory exceeds SizeOfImage");
        }
    }
    return result;
}

ImageInfo toImageInfo(const ParsedImage& image) {
    ImageInfo info;
    const auto& optional = image.nt.OptionalHeader;
    info.preferredImageBase = optional.ImageBase;
    info.imageSize = optional.SizeOfImage;
    info.headerSize = optional.SizeOfHeaders;
    info.entryPointRva = optional.AddressOfEntryPoint;
    info.hasRelocations = hasDirectory(image, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    info.hasImports = hasDirectory(image, IMAGE_DIRECTORY_ENTRY_IMPORT);
    info.hasDelayImports = hasDirectory(image, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    info.hasResources = hasDirectory(image, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    for (const auto& section : image.sections) {
        const auto* nameBegin = reinterpret_cast<const char*>(section.Name);
        const auto* nameEnd = std::find(nameBegin, nameBegin + IMAGE_SIZEOF_SHORT_NAME, '\0');
        info.sections.push_back({std::string(nameBegin, nameEnd), section.VirtualAddress, section.Misc.VirtualSize,
            section.SizeOfRawData, section.Characteristics});
    }
    return info;
}

const IMAGE_NT_HEADERS64& mappedNt(const ModuleState& state) {
    const auto* dos = mappedObject<IMAGE_DOS_HEADER>(state, 0, PeErrorCode::InvalidNtHeader, "Mapped DOS header");
    if (dos->e_lfanew < 0) {
        fail(PeErrorCode::InvalidNtHeader, "Mapped DOS e_lfanew is negative");
    }
    const auto* nt = mappedObject<IMAGE_NT_HEADERS64>(
        state, static_cast<std::uint32_t>(dos->e_lfanew), PeErrorCode::InvalidNtHeader, "Mapped NT headers");
    return *nt;
}

IMAGE_NT_HEADERS64& mappedNt(ModuleState& state) {
    return const_cast<IMAGE_NT_HEADERS64&>(mappedNt(static_cast<const ModuleState&>(state)));
}

IMAGE_DATA_DIRECTORY directory(const ModuleState& state, std::size_t index) {
    const auto& optional = mappedNt(state).OptionalHeader;
    if (index >= optional.NumberOfRvaAndSizes || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return {};
    }
    return optional.DataDirectory[index];
}

void log(std::string_view message) noexcept {
#if defined(PELOADER_VERBOSE_LOGGING)
    std::string line = "[PE] ";
    line.append(message);
    line.push_back('\n');
    ::OutputDebugStringA(line.c_str());
#else
    (void)message;
#endif
}

} // namespace pe::detail
