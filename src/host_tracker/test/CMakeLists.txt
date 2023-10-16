
add_cpputest( host_cache_test
    SOURCES
        ../host_cache.cc
        ../host_cache_segmented.h
        ../host_tracker.cc
        ../../network_inspectors/rna/test/rna_flow_stubs.cc
        ../../sfip/sf_ip.cc
)

add_cpputest( host_cache_module_test
    SOURCES
        ../host_cache_module.cc
        ../host_cache_segmented.h
        ../host_tracker.cc
        ../../framework/module.cc
        ../../framework/value.cc
        ../../hash/lru_cache_shared.cc
        ../../network_inspectors/rna/test/rna_flow_stubs.cc
        ../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${CMAKE_THREAD_LIBS_INIT}
        ${LUAJIT_LIBRARIES}
)

add_cpputest( host_tracker_test
    SOURCES
        ../host_tracker.cc
        ../../network_inspectors/rna/test/rna_flow_stubs.cc
        ../../sfip/sf_ip.cc
)

add_cpputest( host_cache_segmented_test
    SOURCES
        ../host_cache.cc
        ../host_cache.h
        ../host_tracker.cc
        ../host_cache_segmented.h
        ../../network_inspectors/rna/test/rna_flow_stubs.cc
        ../../sfip/sf_ip.cc
    )

add_cpputest( host_tracker_module_test
    SOURCES
        ../host_cache.cc
        ../host_cache_segmented.h
        ../host_tracker.cc
        ../host_tracker_module.cc
        ../../framework/module.cc
        ../../framework/parameter.cc
        ../../framework/value.cc
        ../../network_inspectors/rna/test/rna_flow_stubs.cc
        ../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${DNET_LIBRARIES}
)

add_cpputest( host_cache_allocator_ht_test
    SOURCES
        ../host_tracker.cc
        ../../network_inspectors/rna/test/rna_flow_stubs.cc
        ../../sfip/sf_ip.cc
)

add_cpputest( cache_allocator_test
    SOURCES
        ../host_tracker.cc
        ../../network_inspectors/rna/test/rna_flow_stubs.cc
)
