AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = liblog.a

x_includedir = $(pkgincludedir)/log

x_include_HEADERS = \
messages.h \
obfuscation.h

liblog_a_SOURCES = \
log.cc \
log_text.cc \
messages.cc \
obfuscation.cc \
sf_textlog.cc \
log.h \
log_text.h \
sf_textlog.h

liblog_a_CXXFLAGS = $(AM_CXXFLAGS) -fvisibility=default

AM_CXXFLAGS = @AM_CXXFLAGS@

