
add_subdirectory(base)
add_subdirectory(ip)
add_subdirectory(icmp)
add_subdirectory(tcp)
add_subdirectory(udp)

set (STREAM_INCLUDES
    stream_api.h
    stream_splitter.h
)

add_library( stream STATIC
    stream.h
    stream_api.cc
    stream_inspectors.cc
    stream_inspectors.h
    stream_splitter.cc
)

target_link_libraries( stream
    stream_base
    stream_ip
    stream_icmp
    stream_tcp
    stream_udp
)

install (FILES ${STREAM_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/stream"
)

