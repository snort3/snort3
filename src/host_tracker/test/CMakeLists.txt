

add_cpputest(host_cache_test host_tracker)
add_cpputest(host_cache_module_test host_tracker)
add_cpputest(host_tracker_module_test host_tracker)
add_cpputest(host_tracker_test host_tracker)

target_link_libraries(host_cache_module_test
    ${CMAKE_BINARY_DIR}/src/framework/libframework.a
    ${CMAKE_BINARY_DIR}/src/catch/libcatch_tests.a
    ${CMAKE_BINARY_DIR}/src/sfip/libsfip.a
    ${CMAKE_BINARY_DIR}/src/hash/libhash.a
    ${DNET_LIBRARIES})

target_link_libraries(host_tracker_module_test
    ${CMAKE_BINARY_DIR}/src/framework/libframework.a
    ${CMAKE_BINARY_DIR}/src/catch/libcatch_tests.a
    ${CMAKE_BINARY_DIR}/src/sfip/libsfip.a
    ${DNET_LIBRARIES})

