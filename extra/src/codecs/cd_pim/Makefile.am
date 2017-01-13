cd_pimlibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_pimlib_LTLIBRARIES = cd_pim.la
cd_pim_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_pim_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_pim_la_SOURCES  = cd_pim.cc
