cd_sliplibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_sliplib_LTLIBRARIES = libcd_slip.la
libcd_slip_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_slip_la_LDFLAGS  = -export-dynamic -shared
libcd_slip_la_SOURCES  = cd_slip.cc
