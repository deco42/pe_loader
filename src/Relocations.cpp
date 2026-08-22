#include "PeInternal.hpp"

#include <cstring>

namespace pe::detail {

void applyRelocations(ModuleState& state) {
    const auto actualBase = reinterpret_cast<std::uint64_t>(state.base);
    const std::uint64_t delta = actualBase - state.preferredBase;
    if (delta == 0) {
        return;
    }

    const auto relocationDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocationDirectory.VirtualAddress == 0 || relocationDirectory.Size == 0 ||
        (mappedNt(state).FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0) {
        fail(PeErrorCode::RelocationRequiredButUnavailable,
            "The preferred image base is unavailable and the DLL has no usable relocation directory");
    }

    auto bytes = mappedSpan(
        state, relocationDirectory.VirtualAddress, relocationDirectory.Size,
        PeErrorCode::InvalidRelocationDirectory, "Base relocation directory");
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        if (!checkedRange(cursor, sizeof(IMAGE_BASE_RELOCATION), bytes.size())) {
            fail(PeErrorCode::InvalidRelocationDirectory, "A relocation block header is truncated");
        }
        IMAGE_BASE_RELOCATION block{};
        std::memcpy(&block, bytes.data() + cursor, sizeof(block));
        if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            !checkedRange(cursor, block.SizeOfBlock, bytes.size()) ||
            ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0) {
            fail(PeErrorCode::InvalidRelocationDirectory, "A relocation block has an invalid size");
        }

        const std::size_t count =
            (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        const auto* entries = reinterpret_cast<const WORD*>(
            bytes.data() + cursor + sizeof(IMAGE_BASE_RELOCATION));
        for (std::size_t i = 0; i < count; ++i) {
            WORD entry{};
            std::memcpy(&entry, entries + i, sizeof(entry));
            const WORD type = entry >> 12;
            const WORD offset = entry & 0x0fff;
            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }
            if (type != IMAGE_REL_BASED_DIR64) {
                fail(PeErrorCode::UnsupportedRelocation,
                    "The AMD64 image contains an unsupported relocation type: " + std::to_string(type));
            }
            if (block.VirtualAddress > UINT32_MAX - offset) {
                fail(PeErrorCode::InvalidRelocationDirectory, "A relocation target RVA overflows");
            }
            auto targetBytes = mappedSpan(
                state, block.VirtualAddress + offset, sizeof(std::uint64_t),
                PeErrorCode::InvalidRelocationDirectory, "DIR64 relocation target");
            std::uint64_t target{};
            std::memcpy(&target, targetBytes.data(), sizeof(target));
            target += delta;
            std::memcpy(targetBytes.data(), &target, sizeof(target));
        }
        cursor += block.SizeOfBlock;
    }
}

} // namespace pe::detail
