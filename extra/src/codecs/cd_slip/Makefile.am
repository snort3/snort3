cd_sliplibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_sliplib_LTLIBRARIES = cd_slip.la
cd_slip_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_slip_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_slip_la_SOURCES  = cd_slip.cc
