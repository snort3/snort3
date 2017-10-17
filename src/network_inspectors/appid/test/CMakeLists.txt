
add_library(appid_test_depends_on_lib ../appid_peg_counts.cc ../../../sfip/sf_ip.cc ../../../utils/util_cstring.cc)

add_cpputest(appid_http_event_test appid_test_depends_on_lib)
add_cpputest(appid_api_test appid_test_depends_on_lib)
#add_cpputest(app_info_table_test appid_test_depends_on_lib)
add_cpputest(appid_detector_test appid_test_depends_on_lib)
add_cpputest(appid_expected_flags_test appid_test_depends_on_lib)

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )


