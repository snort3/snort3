
add_subdirectory(appid)
add_subdirectory(arp_spoof)
add_subdirectory(binder)
add_subdirectory(normalize)
add_subdirectory(packet_capture)
add_subdirectory(packet_tracer)
add_subdirectory(perf_monitor)
add_subdirectory(port_scan)
add_subdirectory(reputation)

if(STATIC_INSPECTORS)
    set(STATIC_INSPECTOR_OBJS
        $<TARGET_OBJECTS:arp_spoof>
        $<TARGET_OBJECTS:packet_capture>
        $<TARGET_OBJECTS:perf_monitor>
    )
endif()

set(STATIC_NETWORK_INSPECTOR_PLUGINS
    $<TARGET_OBJECTS:appid>
    $<TARGET_OBJECTS:binder>
    $<TARGET_OBJECTS:normalize>
    $<TARGET_OBJECTS:packet_tracer>
    $<TARGET_OBJECTS:port_scan>
    $<TARGET_OBJECTS:reputation>
    ${STATIC_INSPECTOR_OBJS}
    CACHE INTERNAL "STATIC_NETWORK_INSPECTOR_PLUGINS"
)

add_library( network_inspectors OBJECT
    network_inspectors.cc
    network_inspectors.h
)
