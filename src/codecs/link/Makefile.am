

if STATIC_CODECS
noinst_LIBRARIES = liblink_codecs.a

liblink_codecs_a_SOURCES = \
cd_arp.cc \
cd_erspan2.cc \
cd_erspan3.cc \
cd_fabricpath.cc \
cd_mpls.cc \
cd_ppp_encap.cc \
cd_pppoe.cc \
cd_trans_bridge.cc \
cd_vlan.cc

else
ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_arp.la
libcd_arp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_arp_la_LDFLAGS = -export-dynamic -shared
libcd_arp_la_SOURCES = cd_arp.cc

ehlib_LTLIBRARIES += libcd_erspan2.la
libcd_erspan2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_erspan2_la_LDFLAGS = -export-dynamic -shared
libcd_erspan2_la_SOURCES = cd_erspan2.cc

ehlib_LTLIBRARIES += libcd_erspan3.la
libcd_erspan3_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_erspan3_la_LDFLAGS = -export-dynamic -shared
libcd_erspan3_la_SOURCES = cd_erspan3.cc

ehlib_LTLIBRARIES += libcd_fabricpath.la
libcd_fabricpath_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_fabricpath_la_LDFLAGS = -export-dynamic -shared
libcd_fabricpath_la_SOURCES = cd_fabricpath.cc

ehlib_LTLIBRARIES += libcd_mpls.la
libcd_mpls_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_mpls_la_LDFLAGS = -export-dynamic -shared
libcd_mpls_la_SOURCES = cd_mpls.cc

ehlib_LTLIBRARIES += libcd_vlan.la
libcd_vlan_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_vlan_la_LDFLAGS = -export-dynamic -shared
libcd_vlan_la_SOURCES = cd_vlan.cc

ehlib_LTLIBRARIES += libcd_ppp_encap.la
libcd_ppp_encap_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_ppp_encap_la_LDFLAGS = -export-dynamic -shared
libcd_ppp_encap_la_SOURCES = cd_ppp_encap.cc

ehlib_LTLIBRARIES += libcd_trans_bridge.la
libcd_trans_bridge_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_trans_bridge_la_LDFLAGS = -export-dynamic -shared
libcd_trans_bridge_la_SOURCES = cd_trans_bridge.cc

ehlib_LTLIBRARIES += libcd_pppoe.la
libcd_pppoe_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_pppoe_la_LDFLAGS = -export-dynamic -shared
libcd_pppoe_la_SOURCES = cd_pppoe.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
