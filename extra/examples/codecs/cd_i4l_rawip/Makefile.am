AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_i4l_rawiplibdir = $(pkglibdir)/codecs

cd_i4l_rawiplib_LTLIBRARIES = libcd_i4l_rawip.la
libcd_i4l_rawip_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_i4l_rawip_la_LDFLAGS = -export-dynamic -shared
libcd_i4l_rawip_la_SOURCES = cd_i4l_rawip.cc
