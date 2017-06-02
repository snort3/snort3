
add_subdirectory(base)
add_subdirectory(ip)
add_subdirectory(icmp)
add_subdirectory(libtcp)
add_subdirectory(tcp)
add_subdirectory(udp)
add_subdirectory(user)
add_subdirectory(file)
add_subdirectory(test)

set (STREAM_INCLUDES
    paf.h
    stream.h
    stream_splitter.h
)

add_library( stream STATIC
    stream.cc
    stream_inspectors.cc
    stream_inspectors.h
    stream_splitter.cc
)

add_library( stream_paf STATIC
    flush_bucket.cc
    flush_bucket.h
    paf.cc
)

target_link_libraries( stream
    stream_base
    stream_ip
    stream_icmp
    stream_libtcp
    stream_tcp
    stream_udp
    stream_user
    stream_file
    protocols
)

install (FILES ${STREAM_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/stream"
)
