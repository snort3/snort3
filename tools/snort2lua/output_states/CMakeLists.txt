
add_library(output_states
    out_csv.cc
    out_fast.cc
    out_full.cc
    out_null.cc
    out_tcpdump.cc
    out_test.cc
    out_syslog.cc
    out_unified2.cc
    out_unixsock.cc
    output_api.h
    output_api.cc
)

target_link_libraries( output_states
    snort2lua_helpers
    conversion_data
)
