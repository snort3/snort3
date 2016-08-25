
add_library(depends_on_lib ../../appid_stats_counter.cc)

add_cpputest(service_rsync_test depends_on_lib)

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )


