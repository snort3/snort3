AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = liblink_codecs.a

liblink_codecs_a_SOURCES = \
cd_arp.cc \
cd_arp_module.h \
cd_arp_module.cc


plugin_list = \
cd_erspan2.cc \
cd_erspan2_module.h \
cd_erspan2_module.cc \
cd_erspan3.cc \
cd_erspan3_module.h \
cd_erspan3_module.cc \
cd_ethloopback.cc \
cd_mpls.cc \
cd_mpls_module.h \
cd_mpls_module.cc \
cd_pppencap.cc \
cd_pppoepkt.cc \
cd_pppoepkt_module.h \
cd_pppoepkt_module.cc \
cd_transbridge.cc \
cd_vlan.cc \
cd_vlan_module.h \
cd_vlan_module.cc


if ENABLE_NON_ETHER_DECODER
plugin_list += cd_eapol.cc cd_eapol_module.h cd_eapol_module.cc
endif

if STATIC_CODECS
liblink_codecs_a_SOURCES += $(plugin_list)

else

ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_erspan2.la
libcd_erspan2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_erspan2_la_LDFLAGS = -export-dynamic -shared
libcd_erspan2_la_SOURCES = cd_erspan2.cc cd_erspan2_module.h cd_erspan2_module.cc

ehlib_LTLIBRARIES += libcd_erspan3.la
libcd_erspan3_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_erspan3_la_LDFLAGS = -export-dynamic -shared
libcd_erspan3_la_SOURCES = cd_erspan3.cc cd_erspan3_module.h cd_erspan3_module.cc

ehlib_LTLIBRARIES += libcd_mpls.la
libcd_mpls_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_mpls_la_LDFLAGS = -export-dynamic -shared
libcd_mpls_la_SOURCES = cd_mpls.cc cd_mpls_module.h cd_mpls_module.cc

ehlib_LTLIBRARIES += libcd_vlan.la
libcd_vlan_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_vlan_la_LDFLAGS = -export-dynamic -shared
libcd_vlan_la_SOURCES = cd_vlan.cc cd_vlan_module.h cd_vlan_module.cc

ehlib_LTLIBRARIES += libcd_ethloopback.la
libcd_ethloopback_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_ethloopback_la_LDFLAGS = -export-dynamic -shared
libcd_ethloopback_la_SOURCES = cd_ethloopback.cc

ehlib_LTLIBRARIES += libcd_pppencap.la
libcd_pppencap_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_pppencap_la_LDFLAGS = -export-dynamic -shared
libcd_pppencap_la_SOURCES = cd_pppencap.cc

ehlib_LTLIBRARIES += libcd_transbridge.la
libcd_transbridge_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_transbridge_la_LDFLAGS = -export-dynamic -shared
libcd_transbridge_la_SOURCES = cd_transbridge.cc

ehlib_LTLIBRARIES += libcd_pppoepkt.la
libcd_pppoepkt_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_pppoepkt_la_LDFLAGS = -export-dynamic -shared
libcd_pppoepkt_la_SOURCES = cd_pppoepkt.cc cd_pppoepkt_module.h cd_pppoepkt_module.cc


if ENABLE_NON_ETHER_DECODER

ehlib_LTLIBRARIES += libcd_eapol.la
libcd_eapol_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_eapol_la_LDFLAGS = -export-dynamic -shared
libcd_eapol_la_SOURCES = cd_eapol.cc cd_eapol_module.h cd_eapol_module.cc
endif


endif


AM_CXXFLAGS = @AM_CXXFLAGS@
