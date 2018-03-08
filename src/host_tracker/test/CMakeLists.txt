
add_cpputest( host_cache_test
    SOURCES
        ../host_cache.cc
        ../host_tracker.cc
        ../../sfip/sf_ip.cc
)

add_cpputest( host_cache_module_test
    SOURCES
        ../host_cache_module.cc
        ../host_cache.cc
        ../host_tracker.cc
        ../../framework/module.cc
        ../../framework/value.cc
        ../../hash/lru_cache_shared.cc
        ../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
)

add_cpputest( host_tracker_test
    SOURCES
        ../host_tracker.cc
        ../../sfip/sf_ip.cc
)

add_cpputest( host_tracker_module_test
    SOURCES
        ../host_cache.cc
        ../host_tracker.cc
        ../host_tracker_module.cc
        ../../framework/module.cc
        ../../framework/parameter.cc
        ../../framework/value.cc
        ../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${DNET_LIBRARIES}
)

