
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

ehlib_LTLIBRARIES = libcd_auth.la
libcd_auth_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_auth_la_LDFLAGS = -export-dynamic -shared
libcd_auth_la_SOURCES = cd_auth.cc

ehlib_LTLIBRARIES += libcd_esp.la
libcd_esp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_esp_la_LDFLAGS = -export-dynamic -shared
libcd_esp_la_SOURCES = cd_esp.cc

ehlib_LTLIBRARIES += libcd_gre.la
libcd_gre_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_gre_la_LDFLAGS = -export-dynamic -shared
libcd_gre_la_SOURCES = cd_gre.cc

ehlib_LTLIBRARIES += libcd_icmp4.la
libcd_icmp4_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_icmp4_la_LDFLAGS = -export-dynamic -shared
libcd_icmp4_la_SOURCES = cd_icmp4.cc checksum.h

ehlib_LTLIBRARIES += libcd_icmp6.la
libcd_icmp6_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_icmp6_la_LDFLAGS = -export-dynamic -shared
libcd_icmp6_la_SOURCES = cd_icmp6.cc checksum.h

ehlib_LTLIBRARIES += libcd_igmp.la
libcd_igmp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_igmp_la_LDFLAGS = -export-dynamic -shared
libcd_igmp_la_SOURCES = cd_igmp.cc

ehlib_LTLIBRARIES += libcd_ipv6.la
libcd_ipv6_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_ipv6_la_LDFLAGS = -export-dynamic -shared
libcd_ipv6_la_SOURCES = cd_ipv6.cc checksum.h

ehlib_LTLIBRARIES += libcd_mobility.la
libcd_mobility_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_mobility_la_LDFLAGS = -export-dynamic -shared
libcd_mobility_la_SOURCES = cd_mobility.cc

ehlib_LTLIBRARIES += libcd_pgm.la
libcd_pgm_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_pgm_la_LDFLAGS = -export-dynamic -shared
libcd_pgm_la_SOURCES = cd_pgm.cc checksum.h

ehlib_LTLIBRARIES += libcd_sun_nd.la
libcd_sun_nd_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_sun_nd_la_LDFLAGS = -export-dynamic -shared
libcd_sun_nd_la_SOURCES = cd_sun_nd.cc

ehlib_LTLIBRARIES += libcd_dst_opts.la
libcd_dst_opts_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_dst_opts_la_LDFLAGS = -export-dynamic -shared
libcd_dst_opts_la_SOURCES = cd_dst_opts.cc

ehlib_LTLIBRARIES += libcd_frag.la
libcd_frag_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_frag_la_LDFLAGS = -export-dynamic -shared
libcd_frag_la_SOURCES = cd_frag.cc

ehlib_LTLIBRARIES += libcd_no_next.la
libcd_no_next_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_no_next_la_LDFLAGS = -export-dynamic -shared
libcd_no_next_la_SOURCES = cd_no_next.cc

ehlib_LTLIBRARIES += libcd_routing.la
libcd_routing_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_routing_la_LDFLAGS = -export-dynamic -shared
libcd_routing_la_SOURCES = cd_routing.cc

ehlib_LTLIBRARIES += libcd_swipe.la
libcd_swipe_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_swipe_la_LDFLAGS = -export-dynamic -shared
libcd_swipe_la_SOURCES = cd_swipe.cc

ehlib_LTLIBRARIES += libcd_udp.la
libcd_udp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_udp_la_LDFLAGS = -export-dynamic -shared
libcd_udp_la_SOURCES = cd_udp.cc checksum.h

endif


AM_CXXFLAGS = @AM_CXXFLAGS@
