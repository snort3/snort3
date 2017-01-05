
noinst_LIBRARIES = libsfip.a

x_includedir = $(pkgincludedir)/sfip

x_include_HEADERS = \
sf_returns.h \
sf_cidr.h \
sf_ip.h

libsfip_a_SOURCES = \
sf_cidr.cc \
sf_ip.cc \
sf_ipvar.cc \
sf_ipvar.h \
sf_vartable.cc \
sf_vartable.h

if ENABLE_UNIT_TESTS
libsfip_a_SOURCES += sfip_test.cc
endif

