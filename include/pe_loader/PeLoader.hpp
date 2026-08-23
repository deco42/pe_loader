#pragma once

#include "pe_loader/LoadedModule.hpp"
#include "pe_loader/PeError.hpp"
#include "pe_loader/PeImage.hpp"

#include <cstddef>
#include <span>

namespace pe {

class PeLoader final {
public:
    [[nodiscard]] static ImageInfo inspect(std::span<const std::byte> image);
    [[nodiscard]] static LoadedModule load(std::span<const std::byte> image);
};

} // namespace pe
