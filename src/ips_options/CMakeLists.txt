
include_directories(${LUAJIT_INCLUDE_DIR})

SET( PLUGIN_LIST
    ips_ack.cc
    ips_asn1.cc
    asn1_detect.cc
    asn1_detect.h
    ips_base64.cc
    ips_byte_test.cc
    ips_byte_jump.cc
    ips_cvs.cc
    ips_dsize.cc
    ips_flags.cc
    ips_fragbits.cc
    ips_fragoffset.cc
    ips_http.cc
    ips_icmp_id.cc
    ips_icmp_seq.cc
    ips_icode.cc
    ips_id.cc
    ips_ipopts.cc
    ips_isdataat.cc 
    ips_itype.cc 
    ips_pkt_data.cc
    ips_raw_data.cc
    ips_react.cc
    ips_resp.cc
    ips_rpc.cc
    ips_sameip.cc
    ips_seq.cc
    ips_session.cc
    ips_tos.cc
    ips_ttl.cc
    ips_window.cc
    ips_urilen.cc
)

set (IPS_SOURCES
    ips_byte_extract.cc 
    ips_byte_extract.h
    extract.cc 
    extract.h
    ips_content.cc 
    ips_content.h 
    ips_file_data.cc 
    ips_flow.cc 
    ips_flow.h
    ips_flowbits.cc 
    ips_flowbits.h
    ips_ip_proto.cc 
    ips_ip_proto.h
    ips_luajit.cc 
    ips_luajit.h
    ips_options.cc 
    ips_options.h
    ips_pcre.cc 
    ips_pcre.h
    ips_replace.cc 
    ips_replace.h
    ips_so.cc
)



if (STATIC_IPS_OPTIONS)
    
    add_library ( ips_options STATIC
        ${IPS_SOURCES}
        ${PLUGIN_LIST}
    )

else (STATIC_IPS_OPTIONS)

    add_library ( ips_options SHARED
        ${IPS_SOURCES}
    )

    add_shared_library(ips_ack ips_options ips_ack.cc)
    add_shared_library(ips_asn1 ips_options ips_asn1.cc asn1_detect.cc asn1_detect.h)
    add_shared_library(ips_base64 ips_options ips_base64.cc)
    add_shared_library(ips_byte_test ips_options ips_byte_test.cc)
    add_shared_library(ips_byte_jump ips_options ips_byte_jump.cc)
    add_shared_library(ips_cvs ips_options ips_cvs.cc)
    add_shared_library(ips_dsize ips_options ips_dsize.cc)
    add_shared_library(ips_flags ips_options ips_flags.cc)
    add_shared_library(ips_fragbits ips_options ips_fragbits.cc)
    add_shared_library(ips_fragoffset ips_options ips_fragoffset.cc)
    add_shared_library(ips_http ips_options ips_http.cc)
    add_shared_library(ips_icode ips_options ips_icode.cc)
    add_shared_library(ips_id ips_options ips_id.cc)
    add_shared_library(ips_ipopts ips_options ips_ipopts.cc)
    add_shared_library(ips_isdataat ips_options ips_isdataat.cc)
    add_shared_library(ips_itype ips_options ips_itype.cc)
    add_shared_library(ips_pkt_data ips_options ips_pkt_data.cc)
    add_shared_library(ips_raw_data ips_options ips_raw_data.cc)
    add_shared_library(ips_react ips_options ips_react.cc)
    add_shared_library(ips_resp ips_options ips_resp.cc)
    add_shared_library(ips_rpc ips_options ips_rpc.cc)
    add_shared_library(ips_sameip ips_options ips_sameip.cc)
    add_shared_library(ips_seq ips_options ips_seq.cc)
    add_shared_library(ips_session ips_options ips_session.cc)
    add_shared_library(ips_tos ips_options ips_tos.cc)
    add_shared_library(ips_ttl ips_options ips_ttl.cc)
    add_shared_library(ips_window ips_options ips_window.cc)
    add_shared_library(ips_urilen ips_options ips_urilen.cc)


endif (STATIC_IPS_OPTIONS)

