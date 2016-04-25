cd_ppplibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_ppplib_LTLIBRARIES = libcd_ppp.la
libcd_ppp_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_ppp_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libcd_ppp_la_SOURCES  = cd_ppp.cc
