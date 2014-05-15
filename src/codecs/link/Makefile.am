AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = liblink_codecs.a

liblink_codecs_a_SOURCES = \
cd_arp.cc


plugin_list = \
cd_erspan2.cc \
cd_erspan3.cc \
cd_ethloopback.cc \
cd_mpls.cc \
cd_pppencap.cc \
cd_pppoepkt.cc \
cd_transbridge.cc \
cd_vlan.cc


if ENABLE_NON_ETHER_DECODER
plugin_list += cd_eapol.cc
endif

if STATIC_DECODERS
liblink_codecs_a_SOURCES += $(plugin_list)

else

ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_erspan2.la
libcd_erspan2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_erspan2_la_LDFLAGS = -export-dynamic -shared
libcd_erspan2_la_SOURCES = cd_erspan2.cc

# TODO:  PUT THESE IN T LIST
#    add_shared_library(cd_eapol codecs cd_eapol.cc)
#    add_shared_library(cd_erspan3 codecs cd_erspan3.cc)
#    add_shared_library(cd_ethloopback codecs cd_ethloopback.cc)
#    add_shared_library(cd_mpls codecs cd_mpls.cc)
#    add_shared_library(cd_pppencap codecs cd_pppencap.cc)
#    add_shared_library(cd_pppoepkt codecs cd_pppoepkt.cc)
#    add_shared_library(cd_transbridge codecs cd_transbridge.cc)
#    add_shared_library(cd_vlan codecs cd_vlan.cc)

#    if(ENABLE_NON_ETHER_DECODER)
#        add_shared_library(cd_eapol codecs cd_eapol.cc)
#    endif()

endif


AM_CXXFLAGS = @AM_CXXFLAGS@