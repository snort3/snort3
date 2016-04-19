set (
    HOST_TRACKER_MODULE_LIBS
    catch_tests
    framework
    host_tracker
    sfip
    ${DNET_LIBRARIES}
)

add_cpputest(host_cache_test host_tracker)
add_cpputest(host_cache_module_test ${HOST_TRACKER_MODULE_LIBS} hash)
add_cpputest(host_tracker_module_test ${HOST_TRACKER_MODULE_LIBS})
add_cpputest(host_tracker_test host_tracker)
