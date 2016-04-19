AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_eapollibdir = $(pkglibdir)/codecs

cd_eapollib_LTLIBRARIES = libcd_eapol.la
libcd_eapol_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_eapol_la_LDFLAGS = -export-dynamic -shared
libcd_eapol_la_SOURCES = cd_eapol.cc
