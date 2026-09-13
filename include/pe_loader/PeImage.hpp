#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pe {

struct SectionInfo {
    std::string name;
    std::uint32_t virtualAddress{};
    std::uint32_t virtualSize{};
    std::uint32_t rawSize{};
    std::uint32_t characteristics{};
};

struct ImageInfo {
    std::uint64_t preferredImageBase{};
    std::uint32_t imageSize{};
    std::uint32_t headerSize{};
    std::uint32_t entryPointRva{};
    bool hasRelocations{};
    bool hasImports{};
    bool hasDelayImports{};
    bool hasLoadConfig{};
    bool hasResources{};
    std::vector<SectionInfo> sections;
};

} // namespace pe
