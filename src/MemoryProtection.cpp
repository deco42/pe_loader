#include "PeInternal.hpp"

#include <algorithm>
#include <vector>

namespace pe::detail {
namespace {

DWORD protectionFor(DWORD characteristics) noexcept {
    const bool read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    const bool execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    if (execute) {
        if (write) return PAGE_EXECUTE_READWRITE;
        if (read) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (write) return PAGE_READWRITE;
    if (read) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

DWORD mergeProtection(DWORD current, DWORD incoming) noexcept {
    if (current == 0) return incoming;
    const bool execute = current == PAGE_EXECUTE || current == PAGE_EXECUTE_READ ||
        current == PAGE_EXECUTE_READWRITE || incoming == PAGE_EXECUTE ||
        incoming == PAGE_EXECUTE_READ || incoming == PAGE_EXECUTE_READWRITE;
    const bool write = current == PAGE_READWRITE || current == PAGE_EXECUTE_READWRITE ||
        incoming == PAGE_READWRITE || incoming == PAGE_EXECUTE_READWRITE;
    const bool read = current == PAGE_READONLY || current == PAGE_READWRITE ||
        current == PAGE_EXECUTE_READ || current == PAGE_EXECUTE_READWRITE ||
        incoming == PAGE_READONLY || incoming == PAGE_READWRITE ||
        incoming == PAGE_EXECUTE_READ || incoming == PAGE_EXECUTE_READWRITE;
    if (execute) return write ? PAGE_EXECUTE_READWRITE : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
    return write ? PAGE_READWRITE : (read ? PAGE_READONLY : PAGE_NOACCESS);
}

} // namespace

void applyFinalProtections(ModuleState& state) {
    SYSTEM_INFO info{};
    ::GetSystemInfo(&info);
    const std::size_t pageSize = info.dwPageSize;
    const std::size_t pageCount = (state.size + pageSize - 1) / pageSize;
    std::vector<DWORD> protections(pageCount, PAGE_NOACCESS);

    const std::size_t headerPages = (mappedNt(state).OptionalHeader.SizeOfHeaders + pageSize - 1) / pageSize;
    for (std::size_t page = 0; page < (std::min)(headerPages, pageCount); ++page) {
        protections[page] = PAGE_READONLY;
    }
    for (const auto& section : state.sections) {
        const std::size_t sectionSize = (std::max)(
            static_cast<std::size_t>(section.Misc.VirtualSize),
            static_cast<std::size_t>(section.SizeOfRawData));
        if (sectionSize == 0) continue;
        const std::size_t first = section.VirtualAddress / pageSize;
        const std::size_t last = (section.VirtualAddress + sectionSize - 1) / pageSize;
        const DWORD desired = protectionFor(section.Characteristics);
        for (std::size_t page = first; page <= last && page < pageCount; ++page) {
            protections[page] = mergeProtection(protections[page], desired);
        }
    }

    for (std::size_t first = 0; first < pageCount;) {
        const DWORD protection = protections[first];
        std::size_t last = first + 1;
        while (last < pageCount && protections[last] == protection) ++last;
        DWORD oldProtection{};
        const std::size_t offset = first * pageSize;
        const std::size_t length = (std::min)(state.size - offset, (last - first) * pageSize);
        if (!::VirtualProtect(state.base + offset, length, protection, &oldProtection)) {
            fail(PeErrorCode::MemoryProtectionFailed,
                "VirtualProtect failed while applying final image permissions", ::GetLastError());
        }
        first = last;
    }
    if (!::FlushInstructionCache(::GetCurrentProcess(), state.base, state.size)) {
        fail(PeErrorCode::WindowsApiFailure, "FlushInstructionCache failed", ::GetLastError());
    }
}

} // namespace pe::detail
