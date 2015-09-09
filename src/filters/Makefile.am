
noinst_LIBRARIES = libfilter.a

x_includedir = $(pkgincludedir)/filters

x_include_HEADERS = \
sfrf.h

libfilter_a_SOURCES = \
detection_filter.cc \
detection_filter.h \
rate_filter.cc \
rate_filter.h \
sfthreshold.cc \
sfthreshold.h \
sfrf.cc \
sfthd.cc \
sfthd.h

if BUILD_UNIT_TESTS
libfilter_a_SOURCES += \
sfrf_test.cc \
sfthd_test.cc
endif

