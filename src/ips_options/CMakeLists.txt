
SET( PLUGIN_LIST
    ips_ack.cc
    ips_base64.cc
    ips_ber_data.cc
    ips_ber_skip.cc
    ips_bufferlen.cc
    ips_byte_extract.cc
    ips_byte_jump.cc
    ips_byte_math.cc
    ips_byte_test.cc
    ips_classtype.cc
    ips_content.cc
    ips_cvs.cc
    ips_dsize.cc
    ips_enable.cc
    ips_file_data.cc
    ips_file_meta.cc
    ips_file_type.cc
    ips_flags.cc
    ips_flow.cc
    ips_fragbits.cc
    ips_fragoffset.cc
    ips_gid.cc
    ips_hash.cc
    ips_icmp_id.cc
    ips_icmp_seq.cc
    ips_icode.cc
    ips_id.cc
    ips_ipopts.cc
    ips_ip_proto.cc
    ips_isdataat.cc
    ips_itype.cc
    ips_js_data.cc
    ips_metadata.cc
    ips_msg.cc
    ips_pkt_data.cc
    ips_priority.cc
    ips_raw_data.cc
    ips_reference.cc
    ips_rem.cc
    ips_rev.cc
    ips_rpc.cc
    ips_seq.cc
    ips_service.cc
    ips_sid.cc
    ips_soid.cc
    ips_tag.cc
    ips_target.cc
    ips_tos.cc
    ips_ttl.cc
    ips_window.cc
)

set (IPS_SOURCES
    ips_detection_filter.cc
    ips_flowbits.cc
    ips_flowbits.h
    ips_luajit.cc
    ips_options.cc
    ips_options.h
    ips_pcre.cc
    ips_replace.cc
    ips_so.cc
    ips_vba_data.cc
    ips_vba_data.h
)

if ( HAVE_HYPERSCAN )
    set(PLUGIN_LIST
        ${PLUGIN_LIST}
        ips_regex.cc
        ips_sd_pattern.cc
        sd_credit_card.cc sd_credit_card.h)
endif ()

if (STATIC_IPS_OPTIONS)

    add_library ( ips_options OBJECT
        ${IPS_SOURCES}
        ${PLUGIN_LIST}
    )

else (STATIC_IPS_OPTIONS)

    add_library ( ips_options OBJECT
        ${IPS_SOURCES}
    )

    add_dynamic_module(ips_content ips_options ips_content.cc)
    add_dynamic_module(ips_hash ips_options ips_hash.cc)
    add_dynamic_module(ips_ack ips_options ips_ack.cc)
    add_dynamic_module(ips_base64 ips_options ips_base64.cc)
    add_dynamic_module(ips_ber_data ips_options ips_ber_data.cc)
    add_dynamic_module(ips_ber_skip ips_options ips_ber_skip.cc)
    add_dynamic_module(ips_bufferlen ips_options ips_bufferlen.cc)
    add_dynamic_module(ips_byte_extract ips_options ips_byte_extract.cc)
    add_dynamic_module(ips_byte_jump ips_options ips_byte_jump.cc)
    add_dynamic_module(ips_byte_math ips_options ips_byte_math.cc)
    add_dynamic_module(ips_byte_test ips_options ips_byte_test.cc)
    add_dynamic_module(ips_classtype ips_options ips_classtype.cc)
    add_dynamic_module(ips_cvs ips_options ips_cvs.cc)
    add_dynamic_module(ips_dsize ips_options ips_dsize.cc)
    add_dynamic_module(ips_enable ips_options ips_enable.cc)
    add_dynamic_module(ips_file_data ips_options ips_file_data.cc)
    add_dynamic_module(ips_file_meta ips_options ips_file_meta.cc)
    add_dynamic_module(ips_file_type ips_options ips_file_type.cc)
    add_dynamic_module(ips_flags ips_options ips_flags.cc)
    add_dynamic_module(ips_flow ips_options ips_flow.cc)
    add_dynamic_module(ips_fragbits ips_options ips_fragbits.cc)
    add_dynamic_module(ips_fragoffset ips_options ips_fragoffset.cc)
    add_dynamic_module(ips_gid ips_options ips_gid.cc)
    add_dynamic_module(ips_icode ips_options ips_icode.cc)
    add_dynamic_module(ips_icmp_id ips_options ips_icmp_id.cc)
    add_dynamic_module(ips_icmp_seq ips_options ips_icmp_seq.cc)
    add_dynamic_module(ips_id ips_options ips_id.cc)
    add_dynamic_module(ips_ipopts ips_options ips_ipopts.cc)
    add_dynamic_module(ips_ip_proto ips_options ips_ip_proto.cc)
    add_dynamic_module(ips_isdataat ips_options ips_isdataat.cc)
    add_dynamic_module(ips_itype ips_options ips_itype.cc)
    add_dynamic_module(ips_js_data ips_options ips_js_data.cc)
    add_dynamic_module(ips_metadata ips_options ips_metadata.cc)
    add_dynamic_module(ips_msg ips_options ips_msg.cc)
    add_dynamic_module(ips_pkt_data ips_options ips_pkt_data.cc)
    add_dynamic_module(ips_priority ips_options ips_priority.cc)
    add_dynamic_module(ips_raw_data ips_options ips_raw_data.cc)
    add_dynamic_module(ips_reference ips_options ips_reference.cc)
    add_dynamic_module(ips_rem ips_options ips_rem.cc)
    add_dynamic_module(ips_rev ips_options ips_rev.cc)
    add_dynamic_module(ips_rpc ips_options ips_rpc.cc)
    add_dynamic_module(ips_service ips_options ips_service.cc)
    add_dynamic_module(ips_sid ips_options ips_sid.cc)
    add_dynamic_module(ips_seq ips_options ips_seq.cc)
    add_dynamic_module(ips_soid ips_options ips_soid.cc)
    add_dynamic_module(ips_tag ips_options ips_tag.cc)
    add_dynamic_module(ips_target ips_options ips_target.cc)
    add_dynamic_module(ips_tos ips_options ips_tos.cc)
    add_dynamic_module(ips_ttl ips_options ips_ttl.cc)
    add_dynamic_module(ips_window ips_options ips_window.cc)
if ( HAVE_HYPERSCAN )
    add_dynamic_module(ips_regex ips_options ips_regex.cc)
    add_dynamic_module(ips_sd_pattern ips_options ips_sd_pattern.cc sd_credit_card.cc sd_credit_card.h)
endif ( HAVE_HYPERSCAN )

endif (STATIC_IPS_OPTIONS)

add_subdirectory(test)

