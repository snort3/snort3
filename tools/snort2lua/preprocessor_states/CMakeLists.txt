
add_library(preprocessor_states
    pps_arpspoof.cc
    pps_http_inspect.cc
    pps_smtp.cc
    pps_normalizers.cc
    pps_sfportscan.cc
    pps_ftp_telnet.cc
    preprocessor_api.h
    preprocessor_api.cc
)
