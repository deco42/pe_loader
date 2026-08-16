#include "PeInternal.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace pe::detail {

void allocateAndMap(const ParsedImage& image, ModuleState& state) {
    const auto& optional = image.nt.OptionalHeader;
    void* preferred = reinterpret_cast<void*>(static_cast<std::uintptr_t>(optional.ImageBase));
    void* allocation = ::VirtualAlloc(
        preferred, optional.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocation == nullptr) {
        allocation = ::VirtualAlloc(nullptr, optional.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (allocation == nullptr) {
        fail(PeErrorCode::AllocationFailed, "VirtualAlloc could not reserve the PE image", ::GetLastError());
    }

    state.base = static_cast<std::byte*>(allocation);
    state.size = optional.SizeOfImage;
    state.preferredBase = optional.ImageBase;
    state.entryPointRva = optional.AddressOfEntryPoint;
    state.sections = image.sections;

    std::memcpy(state.base, image.file.data(), optional.SizeOfHeaders);
    for (const auto& section : image.sections) {
        if (section.SizeOfRawData == 0) {
            continue;
        }
        const auto source = fileSpan(
            image, section.PointerToRawData, section.SizeOfRawData,
            PeErrorCode::InvalidSection, "Section raw bytes");
        auto destination = mappedSpan(
            state, section.VirtualAddress, section.SizeOfRawData,
            PeErrorCode::InvalidSection, "Section mapped bytes");
        std::memcpy(destination.data(), source.data(), source.size());
    }

    std::ostringstream stream;
    stream << "allocated image at " << allocation << " (preferred " << preferred << ")";
    log(stream.str());
}

} // namespace pe::detail
