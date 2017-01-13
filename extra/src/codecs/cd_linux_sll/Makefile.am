cd_linux_slllibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_linux_slllib_LTLIBRARIES = cd_linux_sll.la
cd_linux_sll_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_linux_sll_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_linux_sll_la_SOURCES  = cd_linux_sll.cc
