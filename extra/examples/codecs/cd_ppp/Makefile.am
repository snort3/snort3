AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_ppplibdir = $(pkglibdir)/codecs

cd_ppplib_LTLIBRARIES = libcd_ppp.la
libcd_ppp_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_ppp_la_LDFLAGS = -export-dynamic -shared
libcd_ppp_la_SOURCES = cd_ppp.cc
