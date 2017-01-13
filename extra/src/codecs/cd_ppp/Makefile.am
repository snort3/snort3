cd_ppplibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_ppplib_LTLIBRARIES = cd_ppp.la
cd_ppp_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_ppp_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_ppp_la_SOURCES  = cd_ppp.cc
