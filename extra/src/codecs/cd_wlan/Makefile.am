cd_wlanlibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_wlanlib_LTLIBRARIES = cd_wlan.la
cd_wlan_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_wlan_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_wlan_la_SOURCES  = cd_wlan.cc
