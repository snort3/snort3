AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libmisc_codecs.a
libmisc_codecs_a_SOURCES = \
cd_default.cc

plugin_list = \
cd_gtp.cc \
cd_gtp_module.h \
cd_gtp_module.cc \
cd_teredo.cc \
cd_ip4_embedded_in_icmp.cc \
cd_ip6_embedded_in_icmp.cc \
cd_prot_embedded_in_icmp.cc

if STATIC_CODECS
libmisc_codecs_a_SOURCES += $(plugin_list)


else
ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_gtp.la
libcd_gtp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_gtp_la_LDFLAGS = -export-dynamic -shared
libcd_gtp_la_SOURCES = cd_gtp.cc cd_gtp_module.h cd_gtp_module.cc

ehlib_LTLIBRARIES += libcd_teredo.la
libcd_teredo_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_teredo_la_LDFLAGS = -export-dynamic -shared
libcd_teredo_la_SOURCES = cd_teredo.cc

ehlib_LTLIBRARIES += libcd_ip4_embedded_in_icmp.la
libcd_ip4_embedded_in_icmp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_ip4_embedded_in_icmp_la_LDFLAGS = -export-dynamic -shared
libcd_ip4_embedded_in_icmp_la_SOURCES = cd_ip4_embedded_in_icmp.cc

ehlib_LTLIBRARIES += libcd_ip6_embedded_in_icmp.la
libcd_ip6_embedded_in_icmp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_ip6_embedded_in_icmp_la_LDFLAGS = -export-dynamic -shared
libcd_ip6_embedded_in_icmp_la_SOURCES = cd_ip6_embedded_in_icmp.cc

ehlib_LTLIBRARIES += libcd_prot_embedded_in_icmp.la
libcd_prot_embedded_in_icmp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_prot_embedded_in_icmp_la_LDFLAGS = -export-dynamic -shared
libcd_prot_embedded_in_icmp_la_SOURCES = cd_prot_embedded_in_icmp.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
