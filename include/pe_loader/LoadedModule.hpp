#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>

namespace pe {

class PeLoader;

class LoadedModule final {
public:
    LoadedModule() noexcept = default;
    ~LoadedModule();

    LoadedModule(const LoadedModule&) = delete;
    LoadedModule& operator=(const LoadedModule&) = delete;
    LoadedModule(LoadedModule&&) noexcept;
    LoadedModule& operator=(LoadedModule&&) noexcept;

    [[nodiscard]] void* baseAddress() const noexcept;
    [[nodiscard]] std::size_t imageSize() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept { return baseAddress() != nullptr; }

    [[nodiscard]] void* getExportAddress(const char* name) const;
    [[nodiscard]] void* getExportAddress(std::uint16_t ordinal) const;

    template <typename T>
    [[nodiscard]] T getExport(const char* name) const {
        static_assert(std::is_pointer_v<T>, "An export must be requested as a pointer type");
        return reinterpret_cast<T>(getExportAddress(name));
    }

    template <typename T>
    [[nodiscard]] T getExport(std::uint16_t ordinal) const {
        static_assert(std::is_pointer_v<T>, "An export must be requested as a pointer type");
        return reinterpret_cast<T>(getExportAddress(ordinal));
    }

    [[nodiscard]] std::span<const std::byte> getResource(
        std::uint16_t type,
        std::uint16_t name,
        std::uint16_t language = 0) const;

    void unload() noexcept;

private:
    struct Impl;
    explicit LoadedModule(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
    friend class PeLoader;
};

} // namespace pe
