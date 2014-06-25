AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libroot_codecs.a
libroot_codecs_a_SOURCES = \
cd_eth.cc \
cd_eth_module.h \
cd_eth_module.cc \
cd_raw4.cc \
cd_raw6.cc \
cd_null.cc



if ENABLE_NON_ETHER_DECODER
if STATIC_CODECS
libroot_codecs_a_SOURCES += \
cd_linux_sll.cc \
cd_wlan.cc \
cd_wlan_module.h \
cd_wlan_module.cc
#root_fddi.cc \
#root_slip.cc \
#root_i4lrawip.cc \
#root_oldpflog.cc \
#root_enc.cc \
#root_ppp.cc \
#root_pflog.cc \
#root_pppserial.cc \
#root_chdlc.cc \
#root_i4lciscoip.cc



else
ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_wlan.la
libcd_wlan_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_wlan_la_LDFLAGS = -export-dynamic -shared
libcd_wlan_la_SOURCES =  cd_wlan.cc cd_wlan_module.h cd_wlan_module.cc

ehlib_LTLIBRARIES += libcd_linux_sll.la
libcd_linux_sll_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_linux_sll_la_LDFLAGS = -export-dynamic -shared
libcd_linux_sll_la_SOURCES =  cd_linux_sll.cc

endif
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
