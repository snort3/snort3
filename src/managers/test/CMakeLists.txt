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
