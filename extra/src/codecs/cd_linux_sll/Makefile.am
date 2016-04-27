cd_linux_slllibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_linux_slllib_LTLIBRARIES = libcd_linux_sll.la
libcd_linux_sll_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_linux_sll_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libcd_linux_sll_la_SOURCES  = cd_linux_sll.cc
