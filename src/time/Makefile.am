noinst_LIBRARIES = libtime.a

x_includedir = $(pkgincludedir)/time

x_include_HEADERS = \
clock_defs.h \
packet_time.h \
stopwatch.h \
tsc_clock.h

libtime_a_SOURCES = \
packet_time.cc \
periodic.cc \
periodic.h \
timersub.h  \
tsc_clock.cc

if ENABLE_UNIT_TESTS
libtime_a_SOURCES += stopwatch_test.cc
endif
