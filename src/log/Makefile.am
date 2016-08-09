
noinst_LIBRARIES = liblog.a

x_includedir = $(pkgincludedir)/log

x_include_HEADERS = \
messages.h \
obfuscator.h \
text_log.h

liblog_a_SOURCES = \
log.cc \
log.h \
log_text.cc \
log_text.h \
messages.cc \
obfuscator.cc \
text_log.cc

if ENABLE_UNIT_TESTS
SUBDIRS = test
endif

