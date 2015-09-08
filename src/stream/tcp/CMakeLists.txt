
add_library( stream_tcp STATIC
    stream_tcp.cc
    stream_tcp.h
    tcp_module.cc
    tcp_module.h
    tcp_defs.h
    tcp_events.h
    tcp_normalization.h
    tcp_normalization.cc
    tcp_reassembly.h
    tcp_reassembly.cc
    tcp_session.cc
    tcp_session.h
    tcp_closed_state.cc
    tcp_listen_state.cc
    tcp_syn_sent_state.cc
    tcp_syn_recv_state.cc
    ips_stream_reassemble.cc
    ips_stream_size.cc
)
