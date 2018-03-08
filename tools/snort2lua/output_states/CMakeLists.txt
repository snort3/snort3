
add_library(output_states OBJECT
    out_csv.cc
    out_deleted.cc
    out_fast.cc
    out_full.cc
    out_null.cc
    out_tcpdump.cc
    out_test.cc
    out_sfunified2.cc
    out_syslog.cc
    out_unified2.cc
    out_unixsock.cc
    output_api.h
    output_api.cc
)

