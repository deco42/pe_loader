set(PE_TEST_MODULE_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/modules")

function(pe_test_dll target source)
    add_library(${target} SHARED ${source} ${ARGN})
    target_include_directories(${target} PRIVATE "${PE_TEST_MODULE_INCLUDE}")
    target_compile_features(${target} PRIVATE cxx_std_20)
    target_compile_definitions(${target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_compile_options(${target} PRIVATE /W4 /permissive- /EHsc /utf-8)
    pe_apply_runtime(${target} STATIC)
endfunction()

pe_test_dll(BasicDll modules/BasicDll/BasicDll.cpp modules/BasicDll/BasicDll.def)
pe_test_dll(BasicDllMd modules/BasicDll/BasicDll.cpp modules/BasicDll/BasicDll.def)
pe_apply_runtime(BasicDllMd DYNAMIC)
pe_test_dll(RelocationDll modules/RelocationDll/RelocationDll.cpp)
pe_test_dll(DependencyDll modules/DependencyDll/DependencyDll.cpp)
pe_test_dll(ImportDll modules/ImportDll/ImportDll.cpp)
target_link_libraries(ImportDll PRIVATE DependencyDll)
pe_test_dll(OrdinalDependencyDll
    modules/OrdinalDependencyDll/OrdinalDependencyDll.cpp
    modules/OrdinalDependencyDll/OrdinalDependencyDll.def)
pe_test_dll(OrdinalImportDll modules/OrdinalImportDll/OrdinalImportDll.cpp)
target_link_libraries(OrdinalImportDll PRIVATE OrdinalDependencyDll)
pe_test_dll(ForwarderDll
    modules/ForwarderDll/ForwarderDll.cpp
    modules/ForwarderDll/ForwarderDll.def)
pe_test_dll(TlsCallbackDll modules/TlsCallbackDll/TlsCallbackDll.cpp)
# This fixture deliberately has no CRT-provided TLS template. Its custom
# IMAGE_TLS_DIRECTORY64 exercises callbacks with Start == End == 0.
target_compile_options(TlsCallbackDll PRIVATE /GS-)
target_link_options(TlsCallbackDll PRIVATE /NODEFAULTLIB /ENTRY:DllMain)
pe_test_dll(StaticTlsDll modules/StaticTlsDll/StaticTlsDll.cpp)

pe_test_dll(DelayImportDll modules/DelayImportDll/DelayImportDll.cpp)
target_link_libraries(DelayImportDll PRIVATE DependencyDll delayimp)
target_link_options(DelayImportDll PRIVATE "/DELAYLOAD:DependencyDll.dll")
pe_test_dll(ResourceDll
    modules/ResourceDll/ResourceDll.cpp
    modules/ResourceDll/ResourceDll.rc)
pe_test_dll(CfgDll modules/CfgDll/CfgDll.cpp)
target_compile_options(CfgDll PRIVATE /guard:cf)
target_link_options(CfgDll PRIVATE /guard:cf)

add_executable(pe_loader_tests integration/PeLoaderTests.cpp)
target_link_libraries(pe_loader_tests PRIVATE PeLoader::PeLoader)
target_include_directories(pe_loader_tests PRIVATE "${PE_TEST_MODULE_INCLUDE}")
target_compile_options(pe_loader_tests PRIVATE /W4 /permissive- /EHsc /utf-8)
target_compile_definitions(pe_loader_tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
pe_apply_runtime(pe_loader_tests ${PELOADER_MSVC_RUNTIME})

add_executable(pe_parser_tests unit/PeParserTests.cpp)
target_link_libraries(pe_parser_tests PRIVATE PeLoader::PeLoader)
target_compile_options(pe_parser_tests PRIVATE /W4 /permissive- /EHsc /utf-8)
target_compile_definitions(pe_parser_tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
pe_apply_runtime(pe_parser_tests ${PELOADER_MSVC_RUNTIME})
add_dependencies(pe_parser_tests BasicDll)
add_test(NAME PeLoader.ParserUnit COMMAND pe_parser_tests "$<TARGET_FILE:BasicDll>")

function(pe_add_module_test name mode target)
    add_test(NAME ${name} COMMAND pe_loader_tests ${mode} "$<TARGET_FILE:${target}>")
    set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY "$<TARGET_FILE_DIR:${target}>")
endfunction()

pe_add_module_test(PeLoader.BasicDll basic BasicDll)
pe_add_module_test(PeLoader.BasicDllMd basic BasicDllMd)
pe_add_module_test(PeLoader.Relocation relocation RelocationDll)
pe_add_module_test(PeLoader.ImportByName import ImportDll)
pe_add_module_test(PeLoader.ImportByOrdinal ordinal OrdinalImportDll)
pe_add_module_test(PeLoader.ForwardedExport forwarded ForwarderDll)
pe_add_module_test(PeLoader.TlsCallback tls TlsCallbackDll)
pe_add_module_test(PeLoader.StaticTls static_tls StaticTlsDll)
pe_add_module_test(PeLoader.DelayImport delay DelayImportDll)
pe_add_module_test(PeLoader.Resources resource ResourceDll)
pe_add_module_test(PeLoader.Cfg cfg CfgDll)
pe_add_module_test(PeLoader.RepeatedLoadUnload repeat BasicDll)
pe_add_module_test(PeLoader.InvalidPe invalid BasicDll)
pe_add_module_test(PeLoader.ParallelLoad parallel BasicDll)
