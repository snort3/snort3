AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_sliplibdir = $(pkglibdir)/codecs

cd_sliplib_LTLIBRARIES = libcd_slip.la
libcd_slip_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_slip_la_LDFLAGS = -export-dynamic -shared
libcd_slip_la_SOURCES = cd_slip.cc
