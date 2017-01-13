

if STATIC_CODECS
noinst_LIBRARIES = liblink_codecs.a

liblink_codecs_a_SOURCES = \
cd_arp.cc \
cd_erspan2.cc \
cd_erspan3.cc \
cd_ciscometadata.cc \
cd_fabricpath.cc \
cd_mpls.cc \
cd_ppp_encap.cc \
cd_pppoe.cc \
cd_trans_bridge.cc \
cd_vlan.cc

else
ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = cd_arp.la
cd_arp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_arp_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_arp_la_SOURCES = cd_arp.cc

ehlib_LTLIBRARIES += cd_erspan2.la
cd_erspan2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_erspan2_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_erspan2_la_SOURCES = cd_erspan2.cc

ehlib_LTLIBRARIES += cd_erspan3.la
cd_erspan3_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_erspan3_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_erspan3_la_SOURCES = cd_erspan3.cc

ehlib_LTLIBRARIES += cd_ciscometadata.la
cd_ciscometadata_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_ciscometadata_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_ciscometadata_la_SOURCES = cd_ciscometadata.cc

ehlib_LTLIBRARIES += cd_fabricpath.la
cd_fabricpath_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_fabricpath_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_fabricpath_la_SOURCES = cd_fabricpath.cc

ehlib_LTLIBRARIES += cd_mpls.la
cd_mpls_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_mpls_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_mpls_la_SOURCES = cd_mpls.cc

ehlib_LTLIBRARIES += cd_vlan.la
cd_vlan_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_vlan_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_vlan_la_SOURCES = cd_vlan.cc

ehlib_LTLIBRARIES += cd_ppp_encap.la
cd_ppp_encap_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_ppp_encap_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_ppp_encap_la_SOURCES = cd_ppp_encap.cc

ehlib_LTLIBRARIES += cd_trans_bridge.la
cd_trans_bridge_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_trans_bridge_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_trans_bridge_la_SOURCES = cd_trans_bridge.cc

ehlib_LTLIBRARIES += cd_pppoe.la
cd_pppoe_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_pppoe_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_pppoe_la_SOURCES = cd_pppoe.cc
endif
