
noinst_LIBRARIES = liblog.a

x_includedir = $(pkgincludedir)/log

x_include_HEADERS = \
log.h \
log_text.h \
messages.h \
obfuscator.h \
text_log.h \
u2_packet.h \
unified2.h

liblog_a_SOURCES = \
log.cc \
log_text.cc \
messages.cc \
obfuscator.cc \
packet_tracer.cc \
packet_tracer.h \
text_log.cc \
u2_packet.cc

if ENABLE_UNIT_TESTS
SUBDIRS = test
endif

