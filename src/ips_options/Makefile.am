
noinst_LIBRARIES = libips_options.a

plugin_list = \
asn1_detect.cc asn1_detect.h \
asn1_util.cc asn1_util.h \
ips_ack.cc \
ips_asn1.cc \
ips_base64.cc \
ips_bufferlen.cc \
ips_byte_extract.cc \
ips_byte_jump.cc \
ips_byte_math.cc \
ips_byte_test.cc \
ips_cvs.cc \
ips_file_type.cc \
ips_flags.cc \
ips_fragbits.cc \
ips_fragoffset.cc \
ips_gid.cc \
ips_icmp_id.cc \
ips_icmp_seq.cc \
ips_icode.cc \
ips_id.cc \
ips_ipopts.cc \
ips_ip_proto.cc \
ips_isdataat.cc \
ips_itype.cc \
ips_msg.cc \
ips_priority.cc \
ips_raw_data.cc \
ips_rem.cc \
ips_rev.cc \
ips_rpc.cc \
ips_seq.cc \
ips_session.cc \
ips_sid.cc \
ips_soid.cc \
ips_tag.cc \
ips_tos.cc \
ips_ttl.cc \
ips_window.cc

libips_options_a_SOURCES = \
extract.cc extract.h \
ips_classtype.cc \
ips_content.cc \
ips_detection_filter.cc \
ips_dsize.cc \
ips_file_data.cc \
ips_flow.cc ips_flow.h \
ips_flowbits.cc ips_flowbits.h \
ips_hash.cc \
ips_luajit.cc \
ips_metadata.cc \
ips_options.cc ips_options.h \
ips_pcre.cc ips_pcre.h \
ips_pkt_data.cc \
ips_reference.cc \
ips_replace.cc \
ips_service.cc \
ips_so.cc

if HAVE_HYPERSCAN
libips_options_a_SOURCES += ips_regex.cc ips_regex.h
libips_options_a_SOURCES += ips_sd_pattern.cc ips_sd_pattern.h sd_credit_card.cc sd_credit_card.h
endif

if STATIC_IPS_OPTIONS
libips_options_a_SOURCES += $(plugin_list)
else
optlibdir = $(pkglibdir)/ips_options

optlib_LTLIBRARIES = ips_ack.la
ips_ack_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_ack_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_ack_la_SOURCES = ips_ack.cc

optlib_LTLIBRARIES += ips_asn1.la
ips_asn1_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_asn1_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_asn1_la_SOURCES = ips_asn1.cc asn1_detect.cc asn1_detect.h asn1_util.h asn1_util.cc

optlib_LTLIBRARIES += ips_base64.la
ips_base64_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_base64_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_base64_la_SOURCES = ips_base64.cc

optlib_LTLIBRARIES += ips_bufferlen.la
ips_bufferlen_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_bufferlen_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_bufferlen_la_SOURCES = ips_bufferlen.cc

optlib_LTLIBRARIES += ips_byte_test.la
ips_byte_test_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_byte_test_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_byte_test_la_SOURCES = ips_byte_test.cc

optlib_LTLIBRARIES += ips_byte_jump.la
ips_byte_jump_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_byte_jump_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_byte_jump_la_SOURCES = ips_byte_jump.cc

optlib_LTLIBRARIES += ips_byte_extract.la
ips_byte_extract_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_byte_extract_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_byte_extract_la_SOURCES = ips_byte_extract.cc

optlib_LTLIBRARIES += ips_byte_math.la
ips_byte_math_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_byte_math_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_byte_math_la_SOURCES = ips_byte_math.cc

#optlib_LTLIBRARIES += ips_content.la
#ips_content_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#ips_content_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#ips_content_la_SOURCES = ips_content.cc

optlib_LTLIBRARIES += ips_cvs.la
ips_cvs_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_cvs_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_cvs_la_SOURCES = ips_cvs.cc

optlib_LTLIBRARIES += ips_file_type.la
ips_file_type_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_file_type_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_file_type_la_SOURCES = ips_file_type.cc

#optlib_LTLIBRARIES += ips_dsize.la
#ips_dsize_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#ips_dsize_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#ips_dsize_la_SOURCES = ips_dsize.cc

optlib_LTLIBRARIES += ips_flags.la
ips_flags_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_flags_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_flags_la_SOURCES = ips_flags.cc

optlib_LTLIBRARIES += ips_fragbits.la
ips_fragbits_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_fragbits_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_fragbits_la_SOURCES = ips_fragbits.cc

optlib_LTLIBRARIES += ips_fragoffset.la
ips_fragoffset_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_fragoffset_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_fragoffset_la_SOURCES = ips_fragoffset.cc

optlib_LTLIBRARIES += ips_gid.la
ips_gid_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_gid_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_gid_la_SOURCES = ips_gid.cc

# can't be linked dynamically yet
#optlib_LTLIBRARIES += ips_hash.la
#ips_hash_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#ips_hash_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#ips_hash_la_SOURCES = ips_hash.cc

optlib_LTLIBRARIES += ips_icmp_id.la
ips_icmp_id_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_icmp_id_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_icmp_id_la_SOURCES = ips_icmp_id.cc

optlib_LTLIBRARIES += ips_icmp_seq.la
ips_icmp_seq_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_icmp_seq_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_icmp_seq_la_SOURCES = ips_icmp_seq.cc

optlib_LTLIBRARIES += ips_icode.la
ips_icode_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_icode_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_icode_la_SOURCES = ips_icode.cc

optlib_LTLIBRARIES += ips_id.la
ips_id_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_id_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_id_la_SOURCES = ips_id.cc

optlib_LTLIBRARIES += ips_ipopts.la
ips_ipopts_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_ipopts_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_ipopts_la_SOURCES = ips_ipopts.cc

optlib_LTLIBRARIES += ips_ip_proto.la
ips_ip_proto_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_ip_proto_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_ip_proto_la_SOURCES = ips_ip_proto.cc

optlib_LTLIBRARIES += ips_isdataat.la
ips_isdataat_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_isdataat_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_isdataat_la_SOURCES = ips_isdataat.cc

optlib_LTLIBRARIES += ips_itype.la
ips_itype_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_itype_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_itype_la_SOURCES = ips_itype.cc

optlib_LTLIBRARIES += ips_msg.la
ips_msg_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_msg_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_msg_la_SOURCES = ips_msg.cc

optlib_LTLIBRARIES += ips_priority.la
ips_priority_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_priority_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_priority_la_SOURCES = ips_priority.cc

optlib_LTLIBRARIES += ips_raw_data.la
ips_raw_data_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_raw_data_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_raw_data_la_SOURCES = ips_raw_data.cc

optlib_LTLIBRARIES += ips_rem.la
ips_rem_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_rem_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_rem_la_SOURCES = ips_rem.cc

optlib_LTLIBRARIES += ips_rev.la
ips_rev_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_rev_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_rev_la_SOURCES = ips_rev.cc

optlib_LTLIBRARIES += ips_rpc.la
ips_rpc_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_rpc_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_rpc_la_SOURCES = ips_rpc.cc

optlib_LTLIBRARIES += ips_seq.la
ips_seq_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_seq_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_seq_la_SOURCES = ips_seq.cc

optlib_LTLIBRARIES += ips_session.la
ips_session_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_session_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_session_la_SOURCES = ips_session.cc

optlib_LTLIBRARIES += ips_sid.la
ips_sid_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_sid_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_sid_la_SOURCES = ips_sid.cc

optlib_LTLIBRARIES += ips_soid.la
ips_soid_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_soid_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_soid_la_SOURCES = ips_soid.cc

optlib_LTLIBRARIES += ips_tos.la
ips_tos_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_tos_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_tos_la_SOURCES = ips_tos.cc

optlib_LTLIBRARIES += ips_tag.la
ips_tag_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_tag_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_tag_la_SOURCES = ips_tag.cc

optlib_LTLIBRARIES += ips_ttl.la
ips_ttl_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_ttl_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_ttl_la_SOURCES = ips_ttl.cc

optlib_LTLIBRARIES += ips_window.la
ips_window_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ips_window_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ips_window_la_SOURCES = ips_window.cc
endif

if BUILD_CPPUTESTS
SUBDIRS = test
endif

