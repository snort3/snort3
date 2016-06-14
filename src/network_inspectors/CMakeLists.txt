
add_subdirectory(appid)
add_subdirectory(arp_spoof)
add_subdirectory(binder)
add_subdirectory(normalize)
add_subdirectory(packet_capture)
add_subdirectory(perf_monitor)
add_subdirectory(port_scan)
add_subdirectory(reputation)

if(STATIC_INSPECTORS)
    set(STATIC_INSPECTOR_LIBS
        arp_spoof
        packet_capture
    )
endif()

add_library( network_inspectors STATIC
    network_inspectors.cc
    network_inspectors.h
)

target_link_libraries( network_inspectors
    ${STATIC_INSPECTOR_LIBS}
    appid
    appid_client_plugins
    appid_detector_plugins
    appid_service_plugins
    appid_util
    binder
    normalize
    perf_monitor
    port_scan
    reputation
    stream_tcp
)
