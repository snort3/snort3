

add_cpputest(host_cache_test host_tracker)
add_cpputest(host_module_test host_tracker)
add_cpputest(host_tracker_test host_tracker)

find_library(FRAMEWORK_LIB NAMES framework PATHS ../../framework)
find_library(CATCH_LIB NAMES catch_tests PATHS ../../catch)
find_library(SFIP_LIB NAMES sfip PATHS ../../sfip)
find_library(UTILS_LIB NAMES utils PATHS ../../utils)
target_link_libraries(host_module_test ${FRAMEWORK_LIB} ${CATCH_LIB} ${SFIP_LIB} ${SFIP_LIB} ${DNET_LIBRARIES})

