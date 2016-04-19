AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_pimlibdir = $(pkglibdir)/codecs

cd_pimlib_LTLIBRARIES = libcd_pim.la
libcd_pim_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_pim_la_LDFLAGS = -export-dynamic -shared
libcd_pim_la_SOURCES = cd_pim.cc
