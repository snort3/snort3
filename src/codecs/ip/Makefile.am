
noinst_LIBRARIES = libip_codecs.a

libip_codecs_a_SOURCES = \
cd_ipv4.cc \
cd_hop_opts.cc \
cd_tcp.cc


plugin_list = \
cd_auth.cc \
cd_dst_opts.cc \
cd_esp.cc \
cd_frag.cc \
cd_gre.cc \
cd_icmp4.cc \
cd_icmp6.cc \
cd_igmp.cc \
cd_ipv6.cc \
cd_mobility.cc \
cd_no_next.cc \
cd_pgm.cc \
cd_routing.cc \
cd_sun_nd.cc \
cd_swipe.cc \
cd_udp.cc \
checksum.h


if STATIC_CODECS
libip_codecs_a_SOURCES += $(plugin_list)

else

ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = cd_auth.la
cd_auth_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_auth_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_auth_la_SOURCES = cd_auth.cc

ehlib_LTLIBRARIES += cd_esp.la
cd_esp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_esp_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_esp_la_SOURCES = cd_esp.cc

ehlib_LTLIBRARIES += cd_gre.la
cd_gre_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_gre_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_gre_la_SOURCES = cd_gre.cc

ehlib_LTLIBRARIES += cd_icmp4.la
cd_icmp4_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_icmp4_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_icmp4_la_SOURCES = cd_icmp4.cc checksum.h

ehlib_LTLIBRARIES += cd_icmp6.la
cd_icmp6_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_icmp6_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_icmp6_la_SOURCES = cd_icmp6.cc checksum.h

ehlib_LTLIBRARIES += cd_igmp.la
cd_igmp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_igmp_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_igmp_la_SOURCES = cd_igmp.cc

ehlib_LTLIBRARIES += cd_ipv6.la
cd_ipv6_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_ipv6_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_ipv6_la_SOURCES = cd_ipv6.cc checksum.h

ehlib_LTLIBRARIES += cd_mobility.la
cd_mobility_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_mobility_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_mobility_la_SOURCES = cd_mobility.cc

ehlib_LTLIBRARIES += cd_pgm.la
cd_pgm_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_pgm_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_pgm_la_SOURCES = cd_pgm.cc checksum.h

ehlib_LTLIBRARIES += cd_sun_nd.la
cd_sun_nd_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_sun_nd_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_sun_nd_la_SOURCES = cd_sun_nd.cc

ehlib_LTLIBRARIES += cd_dst_opts.la
cd_dst_opts_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_dst_opts_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_dst_opts_la_SOURCES = cd_dst_opts.cc

ehlib_LTLIBRARIES += cd_frag.la
cd_frag_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_frag_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_frag_la_SOURCES = cd_frag.cc

ehlib_LTLIBRARIES += cd_no_next.la
cd_no_next_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_no_next_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_no_next_la_SOURCES = cd_no_next.cc

ehlib_LTLIBRARIES += cd_routing.la
cd_routing_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_routing_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_routing_la_SOURCES = cd_routing.cc

ehlib_LTLIBRARIES += cd_swipe.la
cd_swipe_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_swipe_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_swipe_la_SOURCES = cd_swipe.cc

ehlib_LTLIBRARIES += cd_udp.la
cd_udp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_udp_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_udp_la_SOURCES = cd_udp.cc checksum.h

endif

