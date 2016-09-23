noinst_LIBRARIES = libtime.a

x_includedir = $(pkgincludedir)/time

x_include_HEADERS = \
clock_defs.h \
stopwatch.h \
tsc_clock.h

libtime_a_SOURCES = \
clock_defs.h \
packet_time.cc \
packet_time.h \
periodic.cc \
periodic.h \
stopwatch.h \
timersub.h  \
tsc_clock.cc

if ENABLE_UNIT_TESTS
libtime_a_SOURCES += stopwatch_test.cc
endif
