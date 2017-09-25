reg_testlibdir = $(pkglibdir)/inspectors

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

reg_testlib_LTLIBRARIES = reg_test.la
reg_test_la_CXXFLAGS = $(AM_CXXFLAGS)
reg_test_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
reg_test_la_SOURCES  = reg_test.cc
