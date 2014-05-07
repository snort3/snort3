AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libroot_codecs.a
libroot_codecs_a_SOURCES = \
cd_eth.cc \
cd_raw4.cc \
cd_raw6.cc \
cd_null_root.cc



if ENABLE_NON_ETHER_DECODER
if STATIC_DECODERS
libroot_codecs_a_SOURCES += \
root_trk.cc \
root_fddi.cc \
root_linuxsll.cc \
root_ieee80211.cc \
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
libcd_trk_la_SOURCES = root_trk.cc

endif
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
