#include "PeInternal.hpp"

#include <algorithm>

namespace pe::detail {

void unload(ModuleState& state) noexcept {
    if (state.base == nullptr) return;

    if (state.dllAttached && state.entryPointRva != 0) {
        using DllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto* entry = reinterpret_cast<DllMain>(state.base + state.entryPointRva);
        entry(reinterpret_cast<HINSTANCE>(state.base), DLL_PROCESS_DETACH, nullptr);
        state.dllAttached = false;
    }
    runTlsCallbacks(state, DLL_PROCESS_DETACH);
    for (auto it = state.dependencies.rbegin(); it != state.dependencies.rend(); ++it) {
        if (it->handle != nullptr) ::FreeLibrary(it->handle);
    }
    state.dependencies.clear();
    state.staticTls.templateBytes.clear();
    state.staticTls.directoryPresent = false;
    state.staticTls.compilerManaged = false;
    state.tlsCallbacks.clear();
    ::VirtualFree(state.base, 0, MEM_RELEASE);
    state.base = nullptr;
    state.size = 0;
    state.preferredBase = 0;
    state.entryPointRva = 0;
    state.sections.clear();
}

} // namespace pe::detail
