
add_library(preprocessor_states
    pps_arpspoof.cc
    pps_bo.cc
    pps_frag3_engine.cc
    pps_frag3_global.cc
    pps_ftp_telnet.cc
    pps_ftp_telnet_protocol.cc
    pps_http_inspect.cc
    pps_http_inspect_server.cc
    pps_normalizers.cc
    pps_perfmonitor.cc
    pps_rpc_decode.cc
    pps_sfportscan.cc
    pps_smtp.cc
    pps_stream_global.cc
    pps_stream_tcp.cc
    pps_stream_udp.cc
    preprocessor_api.h
    preprocessor_api.cc
)

