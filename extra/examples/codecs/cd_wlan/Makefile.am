AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_wlanlibdir = $(pkglibdir)/codecs

cd_wlanlib_LTLIBRARIES = libcd_wlan.la
libcd_wlan_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_wlan_la_LDFLAGS = -export-dynamic -shared
libcd_wlan_la_SOURCES = cd_wlan.cc
