AUTOMAKE_OPTIONS=foreign no-dependencies

file_list = \
nhttp_inspect.cc nhttp_inspect.h \
nhttp_msg_section.cc nhttp_msg_section.h \
nhttp_msg_start.cc nhttp_msg_start.h \
nhttp_msg_request.cc nhttp_msg_request.h \
nhttp_msg_status.cc nhttp_msg_status.h \
nhttp_msg_head_shared.cc nhttp_msg_head_shared.h \
nhttp_msg_head.cc nhttp_msg_head.h \
nhttp_msg_body.cc nhttp_msg_body.h \
nhttp_msg_chunk_head.cc nhttp_msg_chunk_head.h \
nhttp_msg_chunk_body.cc nhttp_msg_chunk_body.h \
nhttp_msg_trailer.cc nhttp_msg_trailer.h \
nhttp_head_norm.cc nhttp_head_norm.h \
nhttp_str_to_code.cc nhttp_str_to_code.h \
nhttp_api.cc nhttp_api.h \
nhttp_tables.cc \
nhttp_module.cc nhttp_module.h \
nhttp_test_input.cc nhttp_test_input.h \
nhttp_flow_data.cc nhttp_flow_data.h \
nhttp_stream_splitter.cc nhttp_stream_splitter.h \
nhttp_scratch_pad.h nhttp_enum.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libnhttp_inspect.a
libnhttp_inspect_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libnhttp_inspect.la
libnhttp_inspect_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libnhttp_inspect_la_LDFLAGS = -export-dynamic -shared
libnhttp_inspect_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

