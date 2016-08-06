
noinst_LIBRARIES = liblog.a

x_includedir = $(pkgincludedir)/log

x_include_HEADERS = \
log.h \
messages.h \
obfuscator.h \
text_log.h \
unified2.h

liblog_a_SOURCES = \
log.cc \
log_text.cc \
log_text.h \
messages.cc \
obfuscator.cc \
text_log.cc

if ENABLE_UNIT_TESTS
SUBDIRS = test
endif

