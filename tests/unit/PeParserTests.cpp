#include "pe_loader/PeLoader.hpp"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <vector>

namespace {

std::vector<std::byte> readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot open parser fixture");
    std::vector<char> raw{std::istreambuf_iterator<char>(stream), {}};
    std::vector<std::byte> bytes(raw.size());
    std::memcpy(bytes.data(), raw.data(), raw.size());
    return bytes;
}

void expectError(std::span<const std::byte> bytes, pe::PeErrorCode expected) {
    try {
        (void)pe::PeLoader::inspect(bytes);
    } catch (const pe::PeError& error) {
        if (error.code() == expected) return;
        throw std::runtime_error("Parser returned the wrong PeErrorCode");
    }
    throw std::runtime_error("Parser accepted invalid input");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 2) throw std::runtime_error("Expected one PE fixture path");
        const auto valid = readFile(argv[1]);
        const auto info = pe::PeLoader::inspect(valid);
        if (info.imageSize == 0 || info.headerSize == 0 || info.sections.empty()) {
            throw std::runtime_error("Valid fixture inspection returned incomplete metadata");
        }
        expectError({}, pe::PeErrorCode::InvalidArgument);
        auto badDos = valid;
        badDos[0] = std::byte{};
        expectError(badDos, pe::PeErrorCode::InvalidDosHeader);
        expectError(std::span<const std::byte>(valid).first(sizeof(IMAGE_DOS_HEADER)),
            pe::PeErrorCode::InvalidNtHeader);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Parser unit failure: " << error.what() << '\n';
        return 1;
    }
}
