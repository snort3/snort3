
add_subdirectory(base)
add_subdirectory(ip)
add_subdirectory(icmp)
add_subdirectory(tcp)
add_subdirectory(udp)

add_library( stream STATIC
    stream.h
    stream_api.cc
    stream_inspectors.cc
    stream_inspectors.h
)

target_link_libraries( stream
    stream_base
    stream_ip
    stream_icmp
    stream_tcp
    stream_udp
)

