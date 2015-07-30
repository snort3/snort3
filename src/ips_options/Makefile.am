
noinst_LIBRARIES = libips_options.a

plugin_list = \
ips_ack.cc \
ips_asn1.cc \
asn1_detect.cc asn1_detect.h \
asn1_util.cc asn1_util.h \
ips_base64.cc \
ips_byte_test.cc \
ips_byte_jump.cc \
ips_cvs.cc \
ips_flags.cc \
ips_fragbits.cc \
ips_fragoffset.cc \
ips_gid.cc \
ips_hash.cc \
ips_http.cc \
ips_http_header.cc \
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
ips_bufferlen.cc \
ips_window.cc

libips_options_a_SOURCES = \
ips_byte_extract.cc ips_byte_extract.h \
extract.cc extract.h \
ips_classtype.cc \
ips_content.cc ips_content.h  \
ips_detection_filter.cc \
ips_dsize.cc \
ips_file_data.cc \
ips_flow.cc ips_flow.h \
ips_flowbits.cc ips_flowbits.h \
ips_luajit.cc \
ips_metadata.cc \
ips_options.cc ips_options.h \
ips_pkt_data.cc \
ips_pcre.cc ips_pcre.h \
ips_reference.cc \
ips_replace.cc \
ips_so.cc

if STATIC_IPS_OPTIONS
libips_options_a_SOURCES += $(plugin_list)
else
optlibdir = $(pkglibdir)/ips_options

optlib_LTLIBRARIES = libips_ack.la
libips_ack_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_ack_la_LDFLAGS = -export-dynamic -shared
libips_ack_la_SOURCES = ips_ack.cc

optlib_LTLIBRARIES += libips_asn1.la
libips_asn1_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_asn1_la_LDFLAGS = -export-dynamic -shared
libips_asn1_la_SOURCES = ips_asn1.cc asn1_detect.cc asn1_detect.h asn1_util.h asn1_util.cc

optlib_LTLIBRARIES += libips_base64.la
libips_base64_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_base64_la_LDFLAGS = -export-dynamic -shared
libips_base64_la_SOURCES = ips_base64.cc

optlib_LTLIBRARIES += libips_bufferlen.la
libips_bufferlen_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_bufferlen_la_LDFLAGS = -export-dynamic -shared
libips_bufferlen_la_SOURCES = ips_bufferlen.cc

optlib_LTLIBRARIES += libips_byte_test.la
libips_byte_test_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_byte_test_la_LDFLAGS = -export-dynamic -shared
libips_byte_test_la_SOURCES = ips_byte_test.cc

optlib_LTLIBRARIES += libips_byte_jump.la
libips_byte_jump_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_byte_jump_la_LDFLAGS = -export-dynamic -shared
libips_byte_jump_la_SOURCES = ips_byte_jump.cc

optlib_LTLIBRARIES += libips_cvs.la
libips_cvs_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_cvs_la_LDFLAGS = -export-dynamic -shared
libips_cvs_la_SOURCES = ips_cvs.cc

optlib_LTLIBRARIES += libips_dsize.la
libips_dsize_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_dsize_la_LDFLAGS = -export-dynamic -shared
libips_dsize_la_SOURCES = ips_dsize.cc

optlib_LTLIBRARIES += libips_flags.la
libips_flags_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_flags_la_LDFLAGS = -export-dynamic -shared
libips_flags_la_SOURCES = ips_flags.cc

optlib_LTLIBRARIES += libips_fragbits.la
libips_fragbits_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_fragbits_la_LDFLAGS = -export-dynamic -shared
libips_fragbits_la_SOURCES = ips_fragbits.cc

optlib_LTLIBRARIES += libips_fragoffset.la
libips_fragoffset_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_fragoffset_la_LDFLAGS = -export-dynamic -shared
libips_fragoffset_la_SOURCES = ips_fragoffset.cc

optlib_LTLIBRARIES += libips_gid.la
libips_gid_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_gid_la_LDFLAGS = -export-dynamic -shared
libips_gid_la_SOURCES = ips_gid.cc

optlib_LTLIBRARIES += libips_hash.la
libips_hash_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_hash_la_LDFLAGS = -export-dynamic -shared
libips_hash_la_SOURCES = ips_hash.cc

optlib_LTLIBRARIES += libips_http.la
libips_http_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_http_la_LDFLAGS = -export-dynamic -shared
libips_http_la_SOURCES = ips_http.cc

optlib_LTLIBRARIES += libips_http_header.la
libips_http_header_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_http_header_la_LDFLAGS = -export-dynamic -shared
libips_http_header_la_SOURCES = ips_http_header.cc

optlib_LTLIBRARIES += libips_icmp_id.la
libips_icmp_id_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_icmp_id_la_LDFLAGS = -export-dynamic -shared
libips_icmp_id_la_SOURCES = ips_icmp_id.cc

optlib_LTLIBRARIES += libips_icmp_seq.la
libips_icmp_seq_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_icmp_seq_la_LDFLAGS = -export-dynamic -shared
libips_icmp_seq_la_SOURCES = ips_icmp_seq.cc

optlib_LTLIBRARIES += libips_icode.la
libips_icode_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_icode_la_LDFLAGS = -export-dynamic -shared
libips_icode_la_SOURCES = ips_icode.cc

optlib_LTLIBRARIES += libips_id.la
libips_id_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_id_la_LDFLAGS = -export-dynamic -shared
libips_id_la_SOURCES = ips_id.cc

optlib_LTLIBRARIES += libips_ipopts.la
libips_ipopts_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_ipopts_la_LDFLAGS = -export-dynamic -shared
libips_ipopts_la_SOURCES = ips_ipopts.cc

optlib_LTLIBRARIES += libips_ip_proto.la
libips_ip_proto_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_ip_proto_la_LDFLAGS = -export-dynamic -shared
libips_ip_proto_la_SOURCES = ips_ip_proto.cc

optlib_LTLIBRARIES += libips_isdataat.la
libips_isdataat_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_isdataat_la_LDFLAGS = -export-dynamic -shared
libips_isdataat_la_SOURCES = ips_isdataat.cc

optlib_LTLIBRARIES += libips_itype.la
libips_itype_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_itype_la_LDFLAGS = -export-dynamic -shared
libips_itype_la_SOURCES = ips_itype.cc

optlib_LTLIBRARIES += libips_msg.la
libips_msg_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_msg_la_LDFLAGS = -export-dynamic -shared
libips_msg_la_SOURCES = ips_msg.cc

optlib_LTLIBRARIES += libips_priority.la
libips_priority_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_priority_la_LDFLAGS = -export-dynamic -shared
libips_priority_la_SOURCES = ips_priority.cc

optlib_LTLIBRARIES += libips_raw_data.la
libips_raw_data_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_raw_data_la_LDFLAGS = -export-dynamic -shared
libips_raw_data_la_SOURCES = ips_raw_data.cc

optlib_LTLIBRARIES += libips_rem.la
libips_rem_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_rem_la_LDFLAGS = -export-dynamic -shared
libips_rem_la_SOURCES = ips_rem.cc

optlib_LTLIBRARIES += libips_rev.la
libips_rev_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_rev_la_LDFLAGS = -export-dynamic -shared
libips_rev_la_SOURCES = ips_rev.cc

optlib_LTLIBRARIES += libips_rpc.la
libips_rpc_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_rpc_la_LDFLAGS = -export-dynamic -shared
libips_rpc_la_SOURCES = ips_rpc.cc

optlib_LTLIBRARIES += libips_seq.la
libips_seq_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_seq_la_LDFLAGS = -export-dynamic -shared
libips_seq_la_SOURCES = ips_seq.cc

optlib_LTLIBRARIES += libips_session.la
libips_session_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_session_la_LDFLAGS = -export-dynamic -shared
libips_session_la_SOURCES = ips_session.cc

optlib_LTLIBRARIES += libips_sid.la
libips_sid_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_sid_la_LDFLAGS = -export-dynamic -shared
libips_sid_la_SOURCES = ips_sid.cc

optlib_LTLIBRARIES += libips_soid.la
libips_soid_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_soid_la_LDFLAGS = -export-dynamic -shared
libips_soid_la_SOURCES = ips_soid.cc

optlib_LTLIBRARIES += libips_tos.la
libips_tos_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_tos_la_LDFLAGS = -export-dynamic -shared
libips_tos_la_SOURCES = ips_tos.cc

optlib_LTLIBRARIES += libips_tag.la
libips_tag_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_tag_la_LDFLAGS = -export-dynamic -shared
libips_tag_la_SOURCES = ips_tag.cc

optlib_LTLIBRARIES += libips_ttl.la
libips_ttl_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_ttl_la_LDFLAGS = -export-dynamic -shared
libips_ttl_la_SOURCES = ips_ttl.cc

optlib_LTLIBRARIES += libips_window.la
libips_window_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_window_la_LDFLAGS = -export-dynamic -shared
libips_window_la_SOURCES = ips_window.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
