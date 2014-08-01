
add_library( stream_tcp STATIC
    stream_paf.cc
    stream_paf.h
    stream_tcp.cc
    stream_tcp.h
    tcp_module.cc
    tcp_module.h
    tcp_session.cc
    tcp_session.h
    ips_stream_reassemble.cc
    ips_stream_size.cc
)

