cd_eapollibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_eapollib_LTLIBRARIES = cd_eapol.la
cd_eapol_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_eapol_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_eapol_la_SOURCES  = cd_eapol.cc
