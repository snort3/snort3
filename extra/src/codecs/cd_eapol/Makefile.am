cd_eapollibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_eapollib_LTLIBRARIES = libcd_eapol.la
libcd_eapol_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_eapol_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libcd_eapol_la_SOURCES  = cd_eapol.cc
