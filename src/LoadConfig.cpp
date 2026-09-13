#include "PeInternal.hpp"

#include <cstring>

namespace pe::detail {

void validateLoadConfig(ModuleState& state) {
    const auto loadConfigDirectory = directory(state, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (loadConfigDirectory.VirtualAddress == 0 || loadConfigDirectory.Size == 0) {
        return;
    }
    if (loadConfigDirectory.Size < sizeof(DWORD)) {
        fail(PeErrorCode::InvalidLoadConfig, "Load-config directory is smaller than its Size field");
    }
    const auto bytes = mappedSpan(
        state, loadConfigDirectory.VirtualAddress, loadConfigDirectory.Size,
        PeErrorCode::InvalidLoadConfig, "Load-config directory");
    DWORD declaredSize{};
    std::memcpy(&declaredSize, bytes.data(), sizeof(declaredSize));
    if (declaredSize < sizeof(DWORD) || declaredSize > bytes.size()) {
        fail(PeErrorCode::InvalidLoadConfig, "Load-config Size exceeds its data directory");
    }

    const std::size_t guardFlagsEnd = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags) + sizeof(DWORD);
    if (declaredSize >= guardFlagsEnd) {
        IMAGE_LOAD_CONFIG_DIRECTORY64 config{};
        std::memcpy(&config, bytes.data(), (std::min)(bytes.size(), sizeof(config)));
        // Modern MSVC CRT objects can set CF_INSTRUMENTED while leaving the
        // image without a Guard CF function table. The latter is the signal
        // that the image needs loader-visible valid-call-target metadata.
        if ((config.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0) {
            fail(PeErrorCode::UnsupportedFeature,
                "The image is CFG-instrumented. Full CFG loader registration is unavailable through a documented in-process manual-mapping API");
        }
    }
}

} // namespace pe::detail
