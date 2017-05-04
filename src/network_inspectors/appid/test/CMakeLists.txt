
add_library(appid_test_depends_on_lib ../appid_stats_counter.cc ../../../sfip/sf_ip.cc)

add_cpputest(appid_http_event_test appid_test_depends_on_lib)
add_cpputest(appid_api_test appid_test_depends_on_lib)
add_cpputest(app_info_table_test appid_test_depends_on_lib)
add_cpputest(appid_detector_test appid_test_depends_on_lib)

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )


