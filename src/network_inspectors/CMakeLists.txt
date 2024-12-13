
add_subdirectory(appid)
add_subdirectory(arp_spoof)
add_subdirectory(binder)
add_subdirectory(extractor)

if ( HAVE_LIBML OR USE_LIBML_MOCK )
    add_subdirectory(kaizen)
endif()

add_subdirectory(normalize)
add_subdirectory(packet_capture)
add_subdirectory(perf_monitor)
add_subdirectory(port_scan)
add_subdirectory(reputation)
add_subdirectory(rna)

if(STATIC_INSPECTORS)
    set(STATIC_INSPECTOR_OBJS
        $<TARGET_OBJECTS:arp_spoof>
        $<TARGET_OBJECTS:packet_capture>
        $<TARGET_OBJECTS:perf_monitor>
    )
endif()

if ( HAVE_LIBML OR USE_LIBML_MOCK )
    set(KAIZEN_STATIC_OBJ
        $<TARGET_OBJECTS:kaizen>
    )
endif()

set(STATIC_NETWORK_INSPECTOR_PLUGINS
    $<TARGET_OBJECTS:appid>
    $<TARGET_OBJECTS:binder>
    $<TARGET_OBJECTS:extractor>
    ${KAIZEN_STATIC_OBJ}
    $<TARGET_OBJECTS:normalize>
    $<TARGET_OBJECTS:port_scan>
    $<TARGET_OBJECTS:reputation>
    $<TARGET_OBJECTS:rna>
    ${STATIC_INSPECTOR_OBJS}
    CACHE INTERNAL "STATIC_NETWORK_INSPECTOR_PLUGINS"
)

add_library( network_inspectors OBJECT
    network_inspectors.cc
    network_inspectors.h
)
