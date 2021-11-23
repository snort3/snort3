add_cpputest( rna_module_test
    SOURCES
        ../../../framework/parameter.cc
        ../../../host_tracker/host_cache.cc
        ../rna_fingerprint.cc
        rna_module_mock.h
        rna_module_stubs.h
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${DNET_LIBRARIES}
        ${LUAJIT_LIBRARIES}
)
