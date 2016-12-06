set (
    HOST_TRACKER_MODULE_LIBS
    framework
    sfip
    ${DNET_LIBRARIES}
)

add_cpputest(host_cache_test host_tracker sfip)
add_cpputest(host_cache_module_test host_tracker ${HOST_TRACKER_MODULE_LIBS} hash)
add_cpputest(host_tracker_module_test host_tracker ${HOST_TRACKER_MODULE_LIBS})
add_cpputest(host_tracker_test host_tracker sfip)
