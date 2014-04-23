

set (STREAM_INCLUDES
    stream_api.h
)

if ( BUILD_HA )
    set (HA_SOURCES
       stream_ha.cc
       stream_ha.h
    )

endif( BUILD_HA )

add_library( stream STATIC
    stream.cc
    stream_global.cc
    stream_global.h
    stream_tcp.cc
    stream_tcp.h
    stream_udp.cc
    stream_udp.h
    stream_icmp.cc
    stream_icmp.h
    stream_ip.cc
    stream_ip.h
    stream_paf.cc
    stream_paf.h
    stream_common.h
    stream_module.cc
    stream_module.h
    icmp_config.h
    ip_config.h
    tcp_config.h
    udp_config.h
    ${HA_SOURCES}
)

add_library( stream_api STATIC
    stream_api.cc
    ${STREAM_INCLUDES}
)

set_default_visibility_compile_flag( stream_api )

install(FILES ${STREAM_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/stream"
)

target_link_libraries( stream
    stream_api
    log
    utils
    protocols
    normalize
)
