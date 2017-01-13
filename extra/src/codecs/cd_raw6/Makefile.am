cd_raw6libdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_raw6lib_LTLIBRARIES = cd_raw6.la
cd_raw6_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_raw6_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_raw6_la_SOURCES  = cd_raw6.cc
