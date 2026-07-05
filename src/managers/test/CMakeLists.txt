add_cpputest(get_inspector_test
    SOURCES
        get_inspector_stubs.h
        ../inspector_manager.cc
)

add_cpputest(inspector_manager_reload_test
    SOURCES
        inspector_manager_reload_test.cc
        get_inspector_stubs.h
        ../inspector_manager.cc
)

add_cpputest(mp_transport_manager_test
    SOURCES
        mp_transport_manager_test.cc
        ../mp_transport_manager.cc
        ../../framework/module.cc
)

add_cpputest(action_manager_test
    SOURCES
        ../action_manager.cc
        ../../framework/module.cc
        ../../framework/parameter.cc
        ../../framework/value.cc
        ../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
)
