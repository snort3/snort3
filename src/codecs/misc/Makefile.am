
noinst_LIBRARIES = libmisc_codecs.a
libmisc_codecs_a_SOURCES = \
cd_default.cc

plugin_list = \
cd_gtp.cc \
cd_icmp4_ip.cc \
cd_icmp6_ip.cc \
cd_llc.cc \
cd_teredo.cc \
cd_user.cc

if STATIC_CODECS
libmisc_codecs_a_SOURCES += $(plugin_list)

else
cdlibdir = $(pkglibdir)/codecs

cdlib_LTLIBRARIES = cd_gtp.la
cd_gtp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_gtp_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_gtp_la_SOURCES = cd_gtp.cc

cdlib_LTLIBRARIES += cd_icmp4_ip.la
cd_icmp4_ip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_icmp4_ip_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_icmp4_ip_la_SOURCES = cd_icmp4_ip.cc

cdlib_LTLIBRARIES += cd_icmp6_ip.la
cd_icmp6_ip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_icmp6_ip_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_icmp6_ip_la_SOURCES = cd_icmp6_ip.cc

cdlib_LTLIBRARIES += cd_llc.la
cd_llc_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_llc_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_llc_la_SOURCES = cd_llc.cc

cdlib_LTLIBRARIES += cd_teredo.la
cd_teredo_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_teredo_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_teredo_la_SOURCES = cd_teredo.cc

cdlib_LTLIBRARIES += cd_user.la
cd_user_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_user_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_user_la_SOURCES = cd_user.cc
endif

