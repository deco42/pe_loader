#include "PeInternal.hpp"

namespace pe {

ImageInfo PeLoader::inspect(std::span<const std::byte> image) {
    return detail::toImageInfo(detail::parseImage(image));
}

LoadedModule PeLoader::load(std::span<const std::byte> image) {
    const auto parsed = detail::parseImage(image);
    auto impl = std::make_unique<LoadedModule::Impl>();
    auto& state = impl->state;
    detail::allocateAndMap(parsed, state);
    detail::applyRelocations(state);
    detail::resolveImports(state);
    detail::applyFinalProtections(state);

    if (state.entryPointRva != 0) {
        using DllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto* entry = reinterpret_cast<DllMain>(state.base + state.entryPointRva);
        if (!entry(reinterpret_cast<HINSTANCE>(state.base), DLL_PROCESS_ATTACH, nullptr)) {
            detail::fail(PeErrorCode::EntryPointFailed, "DllMain returned FALSE for DLL_PROCESS_ATTACH");
        }
        state.dllAttached = true;
    }
    return LoadedModule(std::move(impl));
}

LoadedModule::LoadedModule(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
LoadedModule::~LoadedModule() = default;
LoadedModule::LoadedModule(LoadedModule&&) noexcept = default;
LoadedModule& LoadedModule::operator=(LoadedModule&&) noexcept = default;

void* LoadedModule::baseAddress() const noexcept { return impl_ ? impl_->state.base : nullptr; }
std::size_t LoadedModule::imageSize() const noexcept { return impl_ ? impl_->state.size : 0; }

void* LoadedModule::getExportAddress(const char* name) const {
    if (!impl_) detail::fail(PeErrorCode::InvalidArgument, "Cannot query an unloaded module");
    return detail::resolveExport(impl_->state, name);
}

void* LoadedModule::getExportAddress(std::uint16_t ordinal) const {
    if (!impl_) detail::fail(PeErrorCode::InvalidArgument, "Cannot query an unloaded module");
    return detail::resolveExport(impl_->state, ordinal);
}

void LoadedModule::unload() noexcept { impl_.reset(); }

} // namespace pe
