AUTOMAKE_OPTIONS = subdir-objects

noinst_LIBRARIES = libpacket_io.a

x_includedir = $(pkgincludedir)/packet_io

x_include_HEADERS = \
active.h

libpacket_io_a_SOURCES = \
active.cc \
active.h \
intf.cc \
intf.h \
sfdaq.cc \
sfdaq.h \
sfdaq_config.cc \
sfdaq_config.h \
sfdaq_module.cc \
sfdaq_module.h \
trough.cc \
trough.h

if ENABLE_UNIT_TESTS
libpacket_io_a_SOURCES += test/sfdaq_module_test.cc
endif

