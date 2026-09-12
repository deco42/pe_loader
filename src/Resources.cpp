#include "PeInternal.hpp"

#include <algorithm>
#include <cstring>

namespace pe::detail {
namespace {

struct ResourceView {
    const ModuleState& state;
    IMAGE_DATA_DIRECTORY directory;

    template <typename T>
    const T* at(std::uint32_t relative, std::string_view context) const {
        if (relative > directory.Size || sizeof(T) > directory.Size - relative) {
            fail(PeErrorCode::InvalidResourceDirectory, std::string(context) + " exceeds the resource directory");
        }
        if (directory.VirtualAddress > UINT32_MAX - relative) {
            fail(PeErrorCode::InvalidResourceDirectory, "Resource RVA overflows");
        }
        return mappedObject<T>(state, directory.VirtualAddress + relative,
            PeErrorCode::InvalidResourceDirectory, context);
    }
};

const IMAGE_RESOURCE_DIRECTORY_ENTRY* findId(
    const ResourceView& view, std::uint32_t directoryOffset, std::uint16_t id) {
    const auto* directory = view.at<IMAGE_RESOURCE_DIRECTORY>(directoryOffset, "Resource directory node");
    const std::size_t count = static_cast<std::size_t>(directory->NumberOfNamedEntries) +
        directory->NumberOfIdEntries;
    const std::size_t entriesOffset = directoryOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
    if (count > (view.directory.Size - (std::min<std::size_t>)(entriesOffset, view.directory.Size)) /
            sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) {
        fail(PeErrorCode::InvalidResourceDirectory, "Resource directory entry count exceeds its bounds");
    }
    for (std::size_t i = directory->NumberOfNamedEntries; i < count; ++i) {
        const auto* entry = view.at<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
            static_cast<std::uint32_t>(entriesOffset + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)),
            "Resource directory entry");
        if (!entry->NameIsString && entry->Id == id) return entry;
    }
    return nullptr;
}

std::uint32_t childDirectory(const IMAGE_RESOURCE_DIRECTORY_ENTRY& entry) {
    if (!entry.DataIsDirectory) {
        fail(PeErrorCode::InvalidResourceDirectory, "Expected a resource subdirectory");
    }
    return entry.OffsetToDirectory;
}

} // namespace

std::span<const std::byte> findResource(
    const ModuleState& state, std::uint16_t type, std::uint16_t name, std::uint16_t language) {
    const auto resourceDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if (resourceDirectory.VirtualAddress == 0 || resourceDirectory.Size < sizeof(IMAGE_RESOURCE_DIRECTORY)) {
        fail(PeErrorCode::InvalidResourceDirectory, "The DLL has no resource directory");
    }
    ResourceView view{state, resourceDirectory};
    const auto* typeEntry = findId(view, 0, type);
    if (typeEntry == nullptr) fail(PeErrorCode::ExportNotFound, "Resource type was not found");
    const auto* nameEntry = findId(view, childDirectory(*typeEntry), name);
    if (nameEntry == nullptr) fail(PeErrorCode::ExportNotFound, "Resource name was not found");
    const auto languageOffset = childDirectory(*nameEntry);

    const IMAGE_RESOURCE_DIRECTORY_ENTRY* languageEntry{};
    if (language != 0) languageEntry = findId(view, languageOffset, language);
    if (languageEntry == nullptr) {
        const auto* languageDirectory = view.at<IMAGE_RESOURCE_DIRECTORY>(languageOffset, "Language directory");
        const std::size_t count = static_cast<std::size_t>(languageDirectory->NumberOfNamedEntries) +
            languageDirectory->NumberOfIdEntries;
        if (count == 0) fail(PeErrorCode::ExportNotFound, "Resource has no language entries");
        languageEntry = view.at<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
            languageOffset + sizeof(IMAGE_RESOURCE_DIRECTORY), "First language entry");
    }
    if (languageEntry->DataIsDirectory) {
        fail(PeErrorCode::InvalidResourceDirectory, "Resource language entry unexpectedly points to a directory");
    }
    const auto* data = view.at<IMAGE_RESOURCE_DATA_ENTRY>(languageEntry->OffsetToData, "Resource data entry");
    return mappedSpan(state, data->OffsetToData, data->Size,
        PeErrorCode::InvalidResourceDirectory, "Resource data");
}

} // namespace pe::detail
