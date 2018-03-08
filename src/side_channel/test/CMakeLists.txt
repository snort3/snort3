add_cpputest( side_channel_test
    SOURCES ../side_channel.cc
)

add_cpputest( side_channel_module_test
    SOURCES
        ../side_channel_module.cc
        ../../framework/module.cc
        ../../framework/value.cc
        ../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
)

