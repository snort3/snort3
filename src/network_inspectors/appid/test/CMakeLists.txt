
add_library(appid_cpputest_deps OBJECT ../appid_peg_counts.cc ../../../sfip/sf_ip.cc ../../../utils/util_cstring.cc)
include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

# add_cpputest( app_info_table_test
#     SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
# )

add_cpputest( appid_api_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_detector_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_expected_flags_test
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

