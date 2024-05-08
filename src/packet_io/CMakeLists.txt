
set ( PACKET_IO_INCLUDES
    active.h
    active_action.h
    packet_constraints.h
    packet_tracer.h
    sfdaq.h
    sfdaq_instance.h
)

if (ENABLE_UNIT_TESTS)
    set(TEST_FILES
        test/sfdaq_module_test.cc
    )
endif (ENABLE_UNIT_TESTS)

if (ENABLE_STATIC_DAQ)
    foreach (STATIC_MODULE_NAME IN LISTS DAQ_STATIC_MODULES)
        string(APPEND DAQ_STATIC_MODULE_EXTERNS "extern const DAQ_ModuleAPI_t ${STATIC_MODULE_NAME}_daq_module_data;\n")
        string(APPEND DAQ_STATIC_MODULE_DATA_ARRAY "    &${STATIC_MODULE_NAME}_daq_module_data,\n")
    endforeach ()
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/sfdaq_static_modules.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/sfdaq_static_modules.h"
    )
    set_source_files_properties(sfdaq.cc PROPERTIES COMPILE_DEFINITIONS ENABLE_STATIC_DAQ)
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
    set(STATIC_DAQ_MODULES_HEADER "sfdaq_static_modules.h.in")
endif ()

add_library (packet_io OBJECT
    ${PACKET_IO_INCLUDES}
    active.cc
    active_counts.h
    packet_constraints.cc
    packet_tracer.cc
    packet_tracer_module.cc
    packet_tracer_module.h
    sfdaq.cc
    sfdaq_config.cc
    sfdaq_config.h
    sfdaq_instance.cc
    sfdaq_module.cc
    sfdaq_module.h
    trough.cc
    trough.h
    ${STATIC_DAQ_MODULES_HEADER}
    ${TEST_FILES}
)

install (FILES ${PACKET_IO_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/packet_io"
)

