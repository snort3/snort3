add_cpputest(host_cache_test host_tracker)
add_cpputest(host_cache_module_test host_tracker)
add_cpputest(host_tracker_module_test host_tracker)
add_cpputest(host_tracker_test host_tracker)

target_link_libraries(host_cache_module_test
    framework
    catch_tests
    sfip
    hash
    ${DNET_LIBRARIES})

target_link_libraries(host_tracker_module_test
    framework
    catch_tests
    sfip
    ${DNET_LIBRARIES})
