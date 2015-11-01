
noinst_LIBRARIES = libstream_tcp.a

libstream_tcp_a_SOURCES = \
stream_tcp.cc \
stream_tcp.h \
segment_overlap_editor.h \
segment_overlap_editor.cc \
tcp_module.cc \
tcp_module.h \
tcp_debug_trace.h \
tcp_defs.h \
tcp_events.h \
tcp_normalizer.h \
tcp_normalizer.cc \
tcp_normalizers.h \
tcp_normalizers.cc \
tcp_segment.h \
tcp_segment.cc \
tcp_reassembler.h \
tcp_reassembler.cc \
tcp_reassemblers.h \
tcp_reassemblers.cc \
tcp_session.cc \
tcp_session.h \
tcp_closed_state.h \
tcp_closed_state.cc \
tcp_listen_state.cc \
tcp_listen_state.h \
tcp_syn_sent_state.cc \
tcp_syn_sent_state.h \
tcp_syn_recv_state.cc \
tcp_syn_recv_state.h \
ips_stream_reassemble.cc \
ips_stream_size.cc

if BUILD_UNIT_TESTS
SUBDIRS = test
endif
