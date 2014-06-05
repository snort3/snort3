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
cd_esp_module.cc


plugin_list = \
cd_ah.cc \
cd_ah_module.h \
cd_ah_module.cc \
cd_dstopts.cc \
cd_frag.cc \
cd_gre.cc \
cd_gre_module.h \
cd_gre_module.cc \
cd_hopopts.cc \
cd_igmp.cc \
cd_igmp_module.h \
cd_igmp_module.cc \
cd_no_next.cc \
cd_pgm.cc \
cd_pgm_module.h \
cd_pgm_module.cc \
cd_routing.cc \
cd_swipe.cc


if STATIC_DECODERS
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

ehlib_LTLIBRARIES += libcd_pgm.la
libcd_pgm_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_pgm_la_LDFLAGS = -export-dynamic -shared
libcd_pgm_la_SOURCES = cd_gre.cc cd_pgm_module.h cd_pgm_module.cc

# TODO:  PUT THESE IN THE LIST
#add_shared_library(cd_dstopts codecs cd_dstopts.cc)
#add_shared_library(cd_frag codecs cd_frag.cc)
#add_shared_library(cd_hopopts codecs cd_hopopts.cc)
#add_shared_library(cd_igmp codecs cd_igmp.cc)
#add_shared_library(cd_no_next codecs cd_no_next.cc)
#add_shared_library(cd_routing codecs cd_routing.cc)
#add_shared_library(cd_swipe codecs cd_swipe.cc)

endif


AM_CXXFLAGS = @AM_CXXFLAGS@
