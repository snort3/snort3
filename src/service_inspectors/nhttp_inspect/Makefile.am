
file_list = \
nhttp_inspect.cc nhttp_inspect.h \
nhttp_msg_section.cc nhttp_msg_section.h \
nhttp_msg_start.cc nhttp_msg_start.h \
nhttp_msg_request.cc nhttp_msg_request.h \
nhttp_msg_status.cc nhttp_msg_status.h \
nhttp_msg_head_shared.cc nhttp_msg_head_shared.h \
nhttp_msg_header.cc nhttp_msg_header.h \
nhttp_msg_body.cc nhttp_msg_body.h \
nhttp_msg_body_cl.cc nhttp_msg_body_cl.h \
nhttp_msg_body_chunk.cc nhttp_msg_body_chunk.h \
nhttp_msg_body_old.cc nhttp_msg_body_old.h \
nhttp_msg_trailer.cc nhttp_msg_trailer.h \
nhttp_head_norm.cc nhttp_head_norm.h \
nhttp_uri.cc nhttp_uri.h \
nhttp_uri_norm.cc nhttp_uri_norm.h \
nhttp_normalizers.cc nhttp_normalizers.h \
nhttp_str_to_code.cc nhttp_str_to_code.h \
nhttp_api.cc nhttp_api.h \
nhttp_tables.cc \
nhttp_module.cc nhttp_module.h \
nhttp_test_input.cc nhttp_test_input.h \
nhttp_flow_data.cc nhttp_flow_data.h \
nhttp_transaction.cc nhttp_transaction.h \
nhttp_stream_splitter_reassemble.cc nhttp_stream_splitter_scan.cc nhttp_stream_splitter.h \
nhttp_cutter.cc nhttp_cutter.h \
nhttp_enum.h \
nhttp_test_manager.cc nhttp_test_manager.h \
nhttp_field.cc nhttp_field.h \
nhttp_infractions.h \
nhttp_event_gen.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libnhttp_inspect.a
libnhttp_inspect_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libnhttp_inspect.la
libnhttp_inspect_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libnhttp_inspect_la_LDFLAGS = $(AM_LDFLAGS) -export-dynamic -shared
libnhttp_inspect_la_SOURCES = $(file_list)
endif

optlibdir = $(pkglibdir)/inspectors

optlib_LTLIBRARIES = libnhttp_inspect_opt.la
libnhttp_inspect_opt_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libnhttp_inspect_opt_la_LDFLAGS = $(AM_LDFLAGS) -export-dynamic -shared
libnhttp_inspect_opt_la_SOURCES = ips_nhttp.cc ips_nhttp.h

