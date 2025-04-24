add_cpputest(get_inspector_test
    SOURCES
        get_inspector_stubs.h
        ../inspector_manager.cc
)

add_cpputest(mp_transport_manager_test
    SOURCES
        mp_transport_manager_test.cc
        ../mp_transport_manager.cc
        ../../framework/module.cc
)
