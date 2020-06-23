add_cpputest( rna_module_test
    SOURCES
        ../../../framework/parameter.cc
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${DNET_LIBRARIES}
)
