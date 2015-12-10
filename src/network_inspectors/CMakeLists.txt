
add_subdirectory(arp_spoof)
add_subdirectory(binder)
add_subdirectory(normalize)
add_subdirectory(perf_monitor)
add_subdirectory(port_scan)
add_subdirectory(reputation)

if(STATIC_INSPECTORS)
    set(STATIC_INSPECTOR_LIBS
        arp_spoof
    )
endif()

add_library( network_inspectors STATIC
    network_inspectors.cc
    network_inspectors.h
)

target_link_libraries( network_inspectors
    ${STATIC_INSPECTOR_LIBS}
    port_scan
    binder
    perf_monitor
    normalize
    reputation 
    stream_tcp
)
