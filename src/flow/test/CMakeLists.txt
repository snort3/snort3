add_cpputest( ha_test
    SOURCES ../ha.cc
)

add_cpputest( ha_module_test
    SOURCES
        ../ha_module.cc
        ../../framework/module.cc
        ../../framework/value.cc
        ../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
)
