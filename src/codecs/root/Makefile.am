AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libroot_codecs.a
libroot_codecs_a_SOURCES = \
cd_eth.cc \
cd_eth_module.h \
cd_eth_module.cc \
cd_raw4.cc \
cd_raw6.cc \
cd_null_root.cc



if ENABLE_NON_ETHER_DECODER
if STATIC_DECODERS
libroot_codecs_a_SOURCES += \
cd_trk.cc \
cd_trk_module.h \
cd_trk_module.cc \
root_fddi.cc \
root_linuxsll.cc \
cd_ieee80211.cc \
cd_ieee80211_module.h \
cd_ieee80211_module.cc \
root_slip.cc \
root_i4lrawip.cc \
root_oldpflog.cc \
root_enc.cc \
root_ppp.cc \
root_pflog.cc \
root_pppserial.cc \
root_chdlc.cc \
root_i4lciscoip.cc



else
ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_trk.la
libcd_trk_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_trk_la_LDFLAGS = -export-dynamic -shared
libcd_trk_la_SOURCES = cd_trk.cc cd_trk_module.h cd_trk_module.cc

endif
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
