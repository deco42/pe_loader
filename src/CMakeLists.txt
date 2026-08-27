add_library(pe_loader STATIC)
add_library(PeLoader::PeLoader ALIAS pe_loader)

target_sources(pe_loader
    PRIVATE
        PeParser.cpp
        ImageMapper.cpp
        Relocations.cpp
        Imports.cpp
        Exports.cpp
        MemoryProtection.cpp
)

target_include_directories(pe_loader
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_compile_features(pe_loader PUBLIC cxx_std_20)
target_compile_definitions(pe_loader
    PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN
)
target_compile_options(pe_loader PRIVATE /W4 /permissive- /EHsc /utf-8)
target_link_libraries(pe_loader PUBLIC ntdll)
