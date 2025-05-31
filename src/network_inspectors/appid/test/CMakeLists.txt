
if ( ENABLE_UNIT_TESTS )
    add_library(appid_cpputest_deps OBJECT EXCLUDE_FROM_ALL
        ../appid_peg_counts.cc
        ../../../sfip/sf_ip.cc
        ../../../utils/util_cstring.cc
    )
endif ( ENABLE_UNIT_TESTS )

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

add_cpputest( appid_api_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_session_api_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_dns_session_test
)

add_cpputest( appid_detector_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_discovery_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_http_event_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_debug_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( service_state_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_http_session_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_eve_process_event_handler_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( tp_lib_handler_test
    SOURCES
        tp_lib_handler_test.cc
        ../../../network_inspectors/rna/test/rna_flow_stubs.cc
        ../tp_lib_handler.cc
        ../tp_appid_module_api.cc
    LIBS
        dl
)

if ( ENABLE_UNIT_TESTS )
    add_library(tp_mock MODULE EXCLUDE_FROM_ALL tp_mock.cc)
    set_property(TARGET tp_mock PROPERTY ENABLE_EXPORTS 1)
    add_dependencies(tp_lib_handler_test tp_mock)
endif ( ENABLE_UNIT_TESTS )

add_cpputest( tp_appid_types_test
    SOURCES tp_appid_types_test.cc
)


