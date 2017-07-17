
noinst_LIBRARIES = liblog.a

x_includedir = $(pkgincludedir)/log

x_include_HEADERS = \
messages.h \
text_log.h \
unified2.h

liblog_a_SOURCES = \
log.cc \
log.h \
log_text.cc \
log_text.h \
messages.cc \
obfuscator.cc \
obfuscator.h \
packet_tracer.cc \
packet_tracer.h \
text_log.cc

if ENABLE_UNIT_TESTS
SUBDIRS = test
endif

