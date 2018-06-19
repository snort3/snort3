add_library(appid_cpputest_deps OBJECT ../appid_peg_counts.cc ../../../sfip/sf_ip.cc ../../../utils/util_cstring.cc)

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

add_cpputest( appid_api_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

add_cpputest( appid_session_api_test
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

add_cpputest( appid_http_session_test
    SOURCES $<TARGET_OBJECTS:appid_cpputest_deps>
)

if ( ENABLE_APPID_THIRD_PARTY )
  add_library(tp_mock MODULE tp_mock.cc)

  add_cpputest( tp_lib_handler_test
    SOURCES tp_lib_handler_test.cc
    ../tp_lib_handler.cc
    LIBS dl
    )

  add_cpputest( tp_appid_types_test
    SOURCES tp_appid_types_test.cc
    )

  set_property(TARGET tp_mock PROPERTY ENABLE_EXPORTS 1)
endif()

