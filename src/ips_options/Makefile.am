## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libips_options.a

plugin_list = \
ips_ack.cc \
ips_asn1.cc \
asn1_detect.cc asn1_detect.h \
ips_base64_data.cc \
ips_base64_decode.cc \
ips_byte_test.cc \
ips_byte_jump.cc \
ips_cvs.cc \
ips_dsize.cc \
ips_flags.cc \
ips_fragbits.cc \
ips_fragoffset.cc \
ips_icmp_id.cc \
ips_icmp_seq.cc \
ips_icode.cc \
ips_id.cc \
ips_ipopts.cc \
ips_isdataat.cc \
ips_itype.cc \
ips_pkt_data.cc \
ips_react.cc \
ips_resp.cc \
ips_rpc.cc \
ips_sameip.cc \
ips_seq.cc \
ips_session.cc \
ips_tos.cc \
ips_ttl.cc \
ips_window.cc \
ips_urilen.cc ips_urilen.h

libips_options_a_SOURCES = \
ips_byte_extract.cc ips_byte_extract.h \
extract.cc extract.h \
ips_content.cc ips_content.h  \
ips_file_data.cc ips_file_data.h \
ips_flow.cc ips_flow.h \
ips_flowbits.cc ips_flowbits.h \
ips_ip_proto.cc ips_ip_proto.h \
ips_luajit.cc ips_luajit.h \
ips_options.cc ips_options.h \
ips_pcre.cc ips_pcre.h \
ips_so.cc \
replace.cc replace.h

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
libips_asn1_la_SOURCES = ips_asn1.cc asn1_detect.cc asn1_detect.h

optlib_LTLIBRARIES += libips_base64_data.la
libips_base64_data_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_base64_data_la_LDFLAGS = -export-dynamic -shared
libips_base64_data_la_SOURCES = ips_base64_data.cc

optlib_LTLIBRARIES += libips_base64_decode.la
libips_base64_decode_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_base64_decode_la_LDFLAGS = -export-dynamic -shared
libips_base64_decode_la_SOURCES = ips_base64_decode.cc

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

optlib_LTLIBRARIES += libips_isdataat.la
libips_isdataat_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_isdataat_la_LDFLAGS = -export-dynamic -shared
libips_isdataat_la_SOURCES = ips_isdataat.cc

optlib_LTLIBRARIES += libips_itype.la
libips_itype_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_itype_la_LDFLAGS = -export-dynamic -shared
libips_itype_la_SOURCES = ips_itype.cc

optlib_LTLIBRARIES += libips_pkt_data.la
libips_pkt_data_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_pkt_data_la_LDFLAGS = -export-dynamic -shared
libips_pkt_data_la_SOURCES = ips_pkt_data.cc

optlib_LTLIBRARIES += libips_react.la
libips_react_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_react_la_LDFLAGS = -export-dynamic -shared
libips_react_la_SOURCES = ips_react.cc

optlib_LTLIBRARIES += libips_resp.la
libips_resp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_resp_la_LDFLAGS = -export-dynamic -shared
libips_resp_la_SOURCES = ips_resp.cc

optlib_LTLIBRARIES += libips_rpc.la
libips_rpc_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_rpc_la_LDFLAGS = -export-dynamic -shared
libips_rpc_la_SOURCES = ips_rpc.cc

optlib_LTLIBRARIES += libips_sameip.la
libips_sameip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_sameip_la_LDFLAGS = -export-dynamic -shared
libips_sameip_la_SOURCES = ips_sameip.cc

optlib_LTLIBRARIES += libips_seq.la
libips_seq_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_seq_la_LDFLAGS = -export-dynamic -shared
libips_seq_la_SOURCES = ips_seq.cc

optlib_LTLIBRARIES += libips_session.la
libips_session_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_session_la_LDFLAGS = -export-dynamic -shared
libips_session_la_SOURCES = ips_session.cc

optlib_LTLIBRARIES += libips_tos.la
libips_tos_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_tos_la_LDFLAGS = -export-dynamic -shared
libips_tos_la_SOURCES = ips_tos.cc

optlib_LTLIBRARIES += libips_ttl.la
libips_ttl_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_ttl_la_LDFLAGS = -export-dynamic -shared
libips_ttl_la_SOURCES = ips_ttl.cc

optlib_LTLIBRARIES += libips_window.la
libips_window_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_window_la_LDFLAGS = -export-dynamic -shared
libips_window_la_SOURCES = ips_window.cc

optlib_LTLIBRARIES += libips_urilen.la
libips_urilen_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libips_urilen_la_LDFLAGS = -export-dynamic -shared
libips_urilen_la_SOURCES = ips_urilen.cc ips_urilen.h
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
