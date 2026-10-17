cmake_minimum_required(VERSION 3.25)

project(PeLoader VERSION 0.1.0 LANGUAGES CXX RC)

if(NOT WIN32)
    message(FATAL_ERROR "PeLoader supports Windows 10/11 only.")
endif()
if(NOT MSVC)
    message(FATAL_ERROR "PeLoader currently requires MSVC from Visual Studio 2022 or newer.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "PeLoader currently supports AMD64/x64 builds only. Configure CMake using a 64-bit generator/platform.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

option(PELOADER_BUILD_TESTS "Build PE loader tests and fixture DLLs" ON)
option(PELOADER_BUILD_TLS_RESEARCH "Build isolated normal-loader TLS research probes" ON)
option(PELOADER_ENABLE_VERBOSE_LOGGING "Enable loader diagnostics through OutputDebugString" OFF)
set(PELOADER_MSVC_RUNTIME "STATIC" CACHE STRING "MSVC runtime for the loader and test driver: STATIC or DYNAMIC")
set_property(CACHE PELOADER_MSVC_RUNTIME PROPERTY STRINGS STATIC DYNAMIC)

if(NOT PELOADER_MSVC_RUNTIME MATCHES "^(STATIC|DYNAMIC)$")
    message(FATAL_ERROR "PELOADER_MSVC_RUNTIME must be STATIC or DYNAMIC")
endif()

function(pe_apply_runtime target runtime_kind)
    if(runtime_kind STREQUAL "STATIC")
        set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    elseif(runtime_kind STREQUAL "DYNAMIC")
        set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    else()
        message(FATAL_ERROR "Unknown runtime kind: ${runtime_kind}")
    endif()
endfunction()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

add_subdirectory(src)

if(BUILD_TESTING AND PELOADER_BUILD_TESTS)
    add_subdirectory(tests)
endif()
