
add_subdirectory(arp_spoof)
add_subdirectory(normalize)
add_subdirectory(perf_monitor)
add_subdirectory(port_scan)

add_library( network_inspectors STATIC
    network_inspectors.cc
    network_inspectors.h
)

target_link_libraries( network_inspectors
    arp_spoof
    normalize
    perf_monitor
    port_scan
)
