AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libtime.a

x_includedir = $(pkgincludedir)/time

x_include_HEADERS = \
cpuclock.h \
profiler.h

libtime_a_SOURCES = \
packet_time.cc \
packet_time.h \
ppm.cc \
ppm.h \
ppm_module.cc \
ppm_module.h \
profiler.cc \
periodic.cc \
periodic.h \
timersub.h

AM_CXXFLAGS = @AM_CXXFLAGS@
