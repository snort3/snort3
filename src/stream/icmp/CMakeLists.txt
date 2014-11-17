
add_library( stream_icmp STATIC
    icmp_module.cc
    icmp_module.h
    icmp_session.cc
    icmp_session.h
    stream_icmp.cc
    stream_icmp.h
)

target_link_libraries( stream_icmp
    protocols
)
