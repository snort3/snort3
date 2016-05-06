noinst_LIBRARIES = libtime.a

x_includedir = $(pkgincludedir)/time

x_include_HEADERS = \
cpuclock.h \
clock_defs.h \
stopwatch.h

libtime_a_SOURCES = \
packet_time.cc \
packet_time.h \
periodic.cc \
periodic.h \
timersub.h \
clock_defs.h \
stopwatch.h

if ENABLE_UNIT_TESTS
libtime_a_SOURCES += stopwatch_test.cc
endif
