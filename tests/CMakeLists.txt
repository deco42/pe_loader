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
pe_test_dll(BasicStaticTlsDll modules/BasicStaticTlsDll/BasicStaticTlsDll.cpp)
pe_test_dll(BasicStaticTlsDllMd modules/BasicStaticTlsDll/BasicStaticTlsDll.cpp)
pe_apply_runtime(BasicStaticTlsDllMd DYNAMIC)
pe_test_dll(ZeroInitializedStaticTlsDll
    modules/ZeroInitializedStaticTlsDll/ZeroInitializedStaticTlsDll.cpp)
# Keep this regression fixture /MD so its raw TLS template consists only of the
# explicitly zero-initialized variables, without static-CRT TLS sentinels.
pe_apply_runtime(ZeroInitializedStaticTlsDll DYNAMIC)

if(PELOADER_BUILD_TLS_RESEARCH)
    function(pe_tls_research_dll target runtime_kind fixture_kind)
        pe_test_dll(${target} modules/TlsResearch/TlsResearchDll.cpp)
        pe_apply_runtime(${target} ${runtime_kind})
        target_include_directories(${target} PRIVATE modules/TlsResearch)
        target_compile_definitions(${target} PRIVATE TLS_RESEARCH_FIXTURE_KIND=${fixture_kind} ${ARGN})
    endfunction()

    pe_tls_research_dll(TlsScalarMT STATIC 1)
    pe_tls_research_dll(TlsScalarMD DYNAMIC 1)
    pe_tls_research_dll(TlsCppObjectMT STATIC 2 TLS_RESEARCH_HAS_OBJECT)
    pe_tls_research_dll(TlsCppObjectMD DYNAMIC 2 TLS_RESEARCH_HAS_OBJECT)
    pe_tls_research_dll(TlsLargeAligned STATIC 3 TLS_RESEARCH_HAS_LARGE)
    pe_tls_research_dll(TlsMultipleObjects STATIC 4 TLS_RESEARCH_HAS_MULTIPLE)
    pe_tls_research_dll(TlsDestructor STATIC 5 TLS_RESEARCH_HAS_OBJECT)
    pe_tls_research_dll(TlsThreaded STATIC 6
        TLS_RESEARCH_HAS_OBJECT TLS_RESEARCH_HAS_INTERNAL_THREAD)
    pe_test_dll(TlsExternalThreadHelper
        modules/TlsResearch/TlsExternalThreadHelper.cpp)
    pe_apply_runtime(TlsExternalThreadHelper DYNAMIC)
    target_include_directories(TlsExternalThreadHelper PRIVATE modules/TlsResearch)
endif()
pe_test_dll(ExceptionDll modules/ExceptionDll/ExceptionDll.cpp)
pe_apply_runtime(ExceptionDll DYNAMIC)
pe_test_dll(ExceptionDllMt modules/ExceptionDll/ExceptionDll.cpp)
pe_test_dll(StaticConstructorDll modules/StaticConstructorDll/StaticConstructorDll.cpp)
pe_test_dll(DelayImportDll modules/DelayImportDll/DelayImportDll.cpp)
target_link_libraries(DelayImportDll PRIVATE DependencyDll delayimp)
target_link_options(DelayImportDll PRIVATE "/DELAYLOAD:DependencyDll.dll")
pe_test_dll(ResourceDll
    modules/ResourceDll/ResourceDll.cpp
    modules/ResourceDll/ResourceDll.rc)
pe_test_dll(ThreadingDll modules/ThreadingDll/ThreadingDll.cpp)
pe_test_dll(CfgDll modules/CfgDll/CfgDll.cpp)
target_compile_options(CfgDll PRIVATE /guard:cf)
target_link_options(CfgDll PRIVATE /guard:cf)
pe_test_dll(ComplexCppDll
    modules/ComplexCppDll/ComplexCppDll.cpp
    modules/ComplexCppDll/ComplexCppDll.rc)
target_link_libraries(ComplexCppDll PRIVATE DependencyDll bcrypt user32)
pe_apply_runtime(ComplexCppDll DYNAMIC)
pe_test_dll(ComplexCppDllMt
    modules/ComplexCppDll/ComplexCppDll.cpp
    modules/ComplexCppDll/ComplexCppDll.rc)
target_link_libraries(ComplexCppDllMt PRIVATE DependencyDll bcrypt user32)

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
pe_add_module_test(PeLoader.Tls.BasicStaticTlsMt basic_static_tls_unsupported BasicStaticTlsDll)
pe_add_module_test(PeLoader.Tls.BasicStaticTlsMd basic_static_tls_unsupported BasicStaticTlsDllMd)
pe_add_module_test(PeLoader.Tls.TlsAllocAbiProbeMt tls_alloc_abi_probe BasicStaticTlsDll)
pe_add_module_test(PeLoader.Tls.TlsAllocAbiProbeMd tls_alloc_abi_probe BasicStaticTlsDllMd)
pe_add_module_test(PeLoader.Tls.ZeroInitializedDetection
    zero_static_tls_detection ZeroInitializedStaticTlsDll)
pe_add_module_test(PeLoader.Exceptions exception ExceptionDll)
pe_add_module_test(PeLoader.ExceptionsMt exception ExceptionDllMt)
pe_add_module_test(PeLoader.GlobalConstructors constructors StaticConstructorDll)
pe_add_module_test(PeLoader.DelayImport delay DelayImportDll)
pe_add_module_test(PeLoader.Resources resource ResourceDll)
pe_add_module_test(PeLoader.Threading threading ThreadingDll)
pe_add_module_test(PeLoader.Cfg cfg CfgDll)
pe_add_module_test(PeLoader.ComplexCpp complex ComplexCppDll)
pe_add_module_test(PeLoader.ComplexCppMt complex ComplexCppDllMt)
pe_add_module_test(PeLoader.RepeatedLoadUnload repeat BasicDll)
pe_add_module_test(PeLoader.InvalidPe invalid BasicDll)
pe_add_module_test(PeLoader.CompareWithLoadLibrary compare ComplexCppDll)
pe_add_module_test(PeLoader.ParallelLoad parallel BasicDll)

if(PELOADER_BUILD_TLS_RESEARCH)
    function(pe_add_tls_research_test name mode)
        add_test(NAME ${name} COMMAND tls_state_probe ${mode} ${ARGN})
    endfunction()

    pe_add_tls_research_test(PeLoader.TlsResearch.ScalarMt lifecycle
        "$<TARGET_FILE:TlsScalarMT>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.ScalarMd lifecycle
        "$<TARGET_FILE:TlsScalarMD>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.CppObjectMt lifecycle
        "$<TARGET_FILE:TlsCppObjectMT>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.CppObjectMd lifecycle
        "$<TARGET_FILE:TlsCppObjectMD>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.LargeAligned lifecycle
        "$<TARGET_FILE:TlsLargeAligned>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.MultipleObjects lifecycle
        "$<TARGET_FILE:TlsMultipleObjects>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.Destructor lifecycle
        "$<TARGET_FILE:TlsDestructor>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.Threaded lifecycle
        "$<TARGET_FILE:TlsThreaded>" 3)
    pe_add_tls_research_test(PeLoader.TlsResearch.ExternalThread external
        "$<TARGET_FILE:TlsCppObjectMT>" "$<TARGET_FILE:TlsExternalThreadHelper>")
    pe_add_tls_research_test(PeLoader.TlsResearch.MultipleModules multi
        "$<TARGET_FILE:TlsScalarMT>" "$<TARGET_FILE:TlsScalarMD>"
        "$<TARGET_FILE:TlsLargeAligned>" "$<TARGET_FILE:TlsMultipleObjects>")
    pe_add_tls_research_test(PeLoader.TlsResearch.VectorGrowth growth
        "$<TARGET_FILE:TlsScalarMT>" 72)
endif()

function(pe_add_production_tls_rejection_test name dll_name)
    set(dll_path "${PROJECT_SOURCE_DIR}/Prod_dlls/${dll_name}")
    if(EXISTS "${dll_path}")
        add_test(NAME ${name} COMMAND pe_loader_tests production_static_tls_unsupported "${dll_path}")
        set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/Prod_dlls")
    endif()
endfunction()

pe_add_production_tls_rejection_test(
    PeLoader.Tls.Production.Annotation.ExpectedUnsupported cobo_annotation_module.dll)
pe_add_production_tls_rejection_test(
    PeLoader.Tls.Production.Memory.ExpectedUnsupported cobo_memory_module.dll)
pe_add_production_tls_rejection_test(
    PeLoader.Tls.Production.Nodes.ExpectedUnsupported cobo_nodes_module.dll)
