AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libip_codecs.a

libip_codecs_a_SOURCES = \
cd_icmp4.cc \
cd_icmp4_module.h \
cd_icmp4_module.cc \
cd_icmp6.cc \
cd_icmp6_module.h \
cd_icmp6_module.cc \
cd_ipv4.cc \
cd_ipv4_module.h \
cd_ipv4_module.cc \
cd_ipv6.cc \
cd_ipv6_module.h \
cd_ipv6_module.cc \
cd_tcp.cc \
cd_tcp_module.h \
cd_tcp_module.cc \
cd_udp.cc \
cd_udp_module.h \
cd_udp_module.cc \
cd_esp.cc \
cd_esp_module.h \
cd_esp_module.cc \
ipv6_util.h \
ipv6_util.cc


plugin_list = \
cd_auth.cc \
cd_auth_module.h \
cd_auth_module.cc \
cd_dstopts.cc \
cd_frag.cc \
cd_gre.cc \
cd_gre_module.h \
cd_gre_module.cc \
cd_hopopts.cc \
cd_igmp.cc \
cd_igmp_module.h \
cd_igmp_module.cc \
cd_mobility.cc \
cd_no_next.cc \
cd_pgm.cc \
cd_pgm_module.h \
cd_pgm_module.cc \
cd_routing.cc \
cd_sun_nd.cc \
cd_swipe.cc


if STATIC_CODECS
libip_codecs_a_SOURCES += $(plugin_list)

else

ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_ah.la
libcd_ah_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_ah_la_LDFLAGS = -export-dynamic -shared
libcd_ah_la_SOURCES = cd_ah.cc cd_ah_module.h cd_ah_module.cc

ehlib_LTLIBRARIES += libcd_gre.la
libcd_gre_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_gre_la_LDFLAGS = -export-dynamic -shared
libcd_gre_la_SOURCES = cd_gre.cc cd_gre_module.h cd_gre_module.cc

ehlib_LTLIBRARIES += libcd_igmp.la
libcd_igmp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_igmp_la_LDFLAGS = -export-dynamic -shared
libcd_igmp_la_SOURCES = cd_igmp.cc cd_igmp_module.h cd_igmp_module.cc

ehlib_LTLIBRARIES += libcd_mobility.la
libcd_mobility_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_mobility_la_LDFLAGS = -export-dynamic -shared
libcd_mobility_la_SOURCES = cd_mobility.cc

ehlib_LTLIBRARIES += libcd_pgm.la
libcd_pgm_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_pgm_la_LDFLAGS = -export-dynamic -shared
libcd_pgm_la_SOURCES = cd_pgm.cc cd_pgm_module.h cd_pgm_module.cc

ehlib_LTLIBRARIES += libcd_sun_nd.la
libcd_sun_nd_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_sun_nd_la_LDFLAGS = -export-dynamic -shared
libcd_sun_nd_la_SOURCES = cd_sun_nd.cc

ehlib_LTLIBRARIES += libcd_dstopts.la
libcd_dstopts_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_dstopts_la_LDFLAGS = -export-dynamic -shared
libcd_dstopts_la_SOURCES = cd_dstopts.cc ipv6_util.h ipv6_util.cc

ehlib_LTLIBRARIES += libcd_frag.la
libcd_frag_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_frag_la_LDFLAGS = -export-dynamic -shared
libcd_frag_la_SOURCES = cd_frag.cc ipv6_util.h ipv6_util.cc

ehlib_LTLIBRARIES += libcd_hopopts.la
libcd_hopopts_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_hopopts_la_LDFLAGS = -export-dynamic -shared
libcd_hopopts_la_SOURCES = cd_hopopts.cc ipv6_util.h ipv6_util.cc

ehlib_LTLIBRARIES += libcd_no_next.la
libcd_no_next_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_no_next_la_LDFLAGS = -export-dynamic -shared
libcd_no_next_la_SOURCES = cd_no_next.cc ipv6_util.h ipv6_util.cc

ehlib_LTLIBRARIES += libcd_routing.la
libcd_routing_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_routing_la_LDFLAGS = -export-dynamic -shared
libcd_routing_la_SOURCES = cd_routing.cc ipv6_util.h ipv6_util.cc

ehlib_LTLIBRARIES += libcd_swipe.la
libcd_swipe_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_swipe_la_LDFLAGS = -export-dynamic -shared
libcd_swipe_la_SOURCES = cd_swipe.cc

endif


AM_CXXFLAGS = @AM_CXXFLAGS@
