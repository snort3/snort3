
noinst_LIBRARIES = liblog.a

x_includedir = $(pkgincludedir)/log

x_include_HEADERS = \
messages.h \
obfuscation.h \
text_log.h

liblog_a_SOURCES = \
log.cc \
log.h \
log_text.cc \
log_text.h \
messages.cc \
obfuscation.cc \
text_log.cc

liblog_a_CXXFLAGS = $(AM_CXXFLAGS) -fvisibility=default

AM_CXXFLAGS = @AM_CXXFLAGS@

