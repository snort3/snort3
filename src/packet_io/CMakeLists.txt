
if (ENABLE_UNIT_TESTS)
    set(TEST_FILES
        test/sfdaq_module_test.cc
    )
endif (ENABLE_UNIT_TESTS)

add_library (packet_io STATIC
    active.cc
    active.h
    intf.cc
    intf.h
    sfdaq.cc
    sfdaq.h
    sfdaq_config.cc
    sfdaq_config.h
    sfdaq_module.cc
    sfdaq_module.h
    trough.cc
    trough.h
    ${TEST_FILES}
)

