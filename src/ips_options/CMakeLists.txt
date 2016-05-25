
SET( PLUGIN_LIST
    ips_ack.cc
    ips_asn1.cc
    asn1_detect.cc
    asn1_detect.h
    asn1_util.h
    asn1_util.cc
    ips_base64.cc
    ips_bufferlen.cc
    ips_byte_test.cc
    ips_byte_jump.cc
    ips_cvs.cc
    ips_file_type.cc
    ips_flags.cc
    ips_fragbits.cc
    ips_fragoffset.cc
    ips_gid.cc
    ips_http.cc
    ips_http_header.cc
    ips_icmp_id.cc
    ips_icmp_seq.cc
    ips_icode.cc
    ips_id.cc
    ips_ipopts.cc
    ips_ip_proto.cc
    ips_isdataat.cc
    ips_itype.cc
    ips_msg.cc
    ips_priority.cc
    ips_raw_data.cc
    ips_rem.cc
    ips_rev.cc
    ips_rpc.cc
    ips_sd_pattern.cc
    sd_credit_card.cc
    sd_credit_card.h
    sd_pattern_match.cc
    sd_pattern_match.h
    ips_seq.cc
    ips_session.cc
    ips_sid.cc
    ips_soid.cc
    ips_tag.cc
    ips_tos.cc
    ips_ttl.cc
    ips_window.cc
)


set (IPS_SOURCES
    ips_byte_extract.cc
    ips_byte_extract.h
    extract.cc
    extract.h
    ips_classtype.cc
    ips_content.cc
    ips_detection_filter.cc
    ips_dsize.cc
    ips_file_data.cc
    ips_flow.cc
    ips_flow.h
    ips_flowbits.cc
    ips_flowbits.h
    ips_hash.cc
    ips_luajit.cc
    ips_metadata.cc
    ips_options.cc
    ips_options.h
    ips_pkt_data.cc
    ips_pcre.cc
    ips_pcre.h
    ips_reference.cc
    ips_replace.cc
    ips_so.cc
)

if ( HAVE_HYPERSCAN )
    set(OPTION_LIST ips_regex.cc ips_regex.h)
endif ()

if (STATIC_IPS_OPTIONS)

    add_library ( ips_options STATIC
        ${IPS_SOURCES}
        ${OPTION_LIST}
        ${PLUGIN_LIST}
    )

else (STATIC_IPS_OPTIONS)

    add_library ( ips_options STATIC
        ${IPS_SOURCES}
        ${OPTION_LIST}
    )

    add_shared_library(ips_ack ips_options ips_ack.cc)
    add_shared_library(ips_asn1 ips_options ips_asn1.cc asn1_detect.cc asn1_detect.h asn1_util.h asn1_util.cc)
    add_shared_library(ips_base64 ips_options ips_base64.cc)
    add_shared_library(ips_bufferlen ips_options ips_bufferlen.cc)
    add_shared_library(ips_byte_test ips_options ips_byte_test.cc)
    add_shared_library(ips_byte_jump ips_options ips_byte_jump.cc)
    add_shared_library(ips_cvs ips_options ips_cvs.cc)
    add_shared_library(ips_file_type ips_options ips_file_type.cc)
    add_shared_library(ips_flags ips_options ips_flags.cc)
    add_shared_library(ips_fragbits ips_options ips_fragbits.cc)
    add_shared_library(ips_fragoffset ips_options ips_fragoffset.cc)
    add_shared_library(ips_gid ips_options ips_gid.cc)
    add_shared_library(ips_http ips_options ips_http.cc)
    add_shared_library(ips_http_header ips_options ips_http_header.cc)
    add_shared_library(ips_icode ips_options ips_icode.cc)
    add_shared_library(ips_icmp_id ips_options ips_icmp_id.cc)
    add_shared_library(ips_icmp_seq ips_options ips_icmp_seq.cc)
    add_shared_library(ips_id ips_options ips_id.cc)
    add_shared_library(ips_ipopts ips_options ips_ipopts.cc)
    add_shared_library(ips_ip_proto ips_options ips_ip_proto.cc)
    add_shared_library(ips_isdataat ips_options ips_isdataat.cc)
    add_shared_library(ips_itype ips_options ips_itype.cc)
    add_shared_library(ips_msg ips_options ips_msg.cc)
    add_shared_library(ips_priority ips_options ips_priority.cc)
    add_shared_library(ips_raw_data ips_options ips_raw_data.cc)
    add_shared_library(ips_rem ips_options ips_rem.cc)
    add_shared_library(ips_rev ips_options ips_rev.cc)
    add_shared_library(ips_rpc ips_options ips_rpc.cc)
    add_shared_library(ips_sd_pattern ips_options ips_sd_pattern.cc sd_credit_card.cc sd_credit_card.h sd_pattern_match.cc sd_pattern_match.h)
    add_shared_library(ips_sid ips_options ips_sid.cc)
    add_shared_library(ips_seq ips_options ips_seq.cc)
    add_shared_library(ips_session ips_options ips_session.cc)
    add_shared_library(ips_soid ips_options ips_soid.cc)
    add_shared_library(ips_tag ips_options ips_tag.cc)
    add_shared_library(ips_tos ips_options ips_tos.cc)
    add_shared_library(ips_ttl ips_options ips_ttl.cc)
    add_shared_library(ips_window ips_options ips_window.cc)

endif (STATIC_IPS_OPTIONS)

target_link_libraries(ips_options
    framework
    helpers
    hash
)
