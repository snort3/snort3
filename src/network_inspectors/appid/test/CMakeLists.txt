
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

add_cpputest( appid_app_descriptor_test
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

# Regression test for the data race on appid_peg_ids (add_app_peg_info vs
# init_pegs/sum_stats) and on appid_dynamic_sum (print vs sum_stats).
# Detecting the regression does NOT require a sanitizer: without the lock a
# concurrent emplace()/rehash corrupts the map mid-walk and the peg_ids->at()
# lookup in sum_stats() throws std::out_of_range, so even a plain build fails.
# Under TSAN the same races are additionally reported with both racing stacks.
add_cpputest( appid_peg_counts_race_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
    LIBS ${CMAKE_THREAD_LIBS_INIT}
)

add_cpputest( appid_eve_process_event_handler_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_dns_payload_event_handler_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( user_data_map_test
    SOURCES ../user_data_map.cc
)

add_cpputest( appid_ssh_event_handler_test
    SOURCES
        appid_ssh_event_handler_test.cc
        $<TARGET_OBJECTS:appid_cpputest_deps>
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


