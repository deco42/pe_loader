#pragma once

#include <cstdint>

struct ModuleContext {
    std::uint32_t apiVersion;
    const wchar_t* userName;
    std::uint64_t permissions;
};

struct TestReport {
    std::uint64_t passed;
    std::uint64_t failed;
};

enum : std::uint64_t {
    PE_TEST_GLOBAL_CTOR = 1ULL << 0,
    PE_TEST_IMPORT_KERNEL32 = 1ULL << 1,
    PE_TEST_IMPORT_USER32 = 1ULL << 2,
    PE_TEST_IMPORT_BCRYPT = 1ULL << 3,
    PE_TEST_EXCEPTION = 1ULL << 4,
    PE_TEST_THREAD = 1ULL << 5,
    PE_TEST_FILESYSTEM = 1ULL << 6,
    PE_TEST_STL = 1ULL << 7,
    PE_TEST_VIRTUAL_CALL = 1ULL << 8,
    PE_TEST_CALLBACK = 1ULL << 9,
    PE_TEST_DEPENDENCY = 1ULL << 10,
    PE_TEST_ATOMIC = 1ULL << 11
};
