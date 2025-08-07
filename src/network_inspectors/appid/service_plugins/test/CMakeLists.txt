
include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

add_cpputest( service_rsync_test )
add_cpputest( alpn_patterns_tests )
add_cpputest( service_snmp_test )
add_cpputest( service_rtmp_test )
add_cpputest( service_netbios_test )
