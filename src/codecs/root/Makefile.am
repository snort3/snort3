AUTOMAKE_OPTIONS=foreign no-dependencies

if STATIC_CODECS
noinst_LIBRARIES = libroot_codecs.a

libroot_codecs_a_SOURCES = \
cd_eth.cc \
cd_linux_sll.cc \
cd_null.cc \
cd_ppp.cc \
cd_raw4.cc \
cd_raw6.cc \
cd_slip.cc \
cd_wlan.cc
#root_fddi.cc \
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

ehlib_LTLIBRARIES = libcd_eth.la
libcd_eth_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_eth_la_LDFLAGS = -export-dynamic -shared
libcd_eth_la_SOURCES =  cd_eth.cc

ehlib_LTLIBRARIES += libcd_linux_sll.la
libcd_linux_sll_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_linux_sll_la_LDFLAGS = -export-dynamic -shared
libcd_linux_sll_la_SOURCES =  cd_linux_sll.cc

ehlib_LTLIBRARIES += libcd_null.la
libcd_null_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_null_la_LDFLAGS = -export-dynamic -shared
libcd_null_la_SOURCES =  cd_null.cc

ehlib_LTLIBRARIES += libcd_ppp.la
libcd_ppp_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_ppp_la_LDFLAGS = -export-dynamic -shared
libcd_ppp_la_SOURCES =  cd_ppp.cc

ehlib_LTLIBRARIES += libcd_raw4.la
libcd_raw4_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_raw4_la_LDFLAGS = -export-dynamic -shared
libcd_raw4_la_SOURCES =  cd_raw4.cc

ehlib_LTLIBRARIES += libcd_raw6.la
libcd_raw6_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_raw6_la_LDFLAGS = -export-dynamic -shared
libcd_raw6_la_SOURCES =  cd_raw6.cc

ehlib_LTLIBRARIES += libcd_slip.la
libcd_slip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_slip_la_LDFLAGS = -export-dynamic -shared
libcd_slip_la_SOURCES =  cd_slip.cc

ehlib_LTLIBRARIES += libcd_wlan.la
libcd_wlan_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_wlan_la_LDFLAGS = -export-dynamic -shared
libcd_wlan_la_SOURCES =  cd_wlan.cc

endif

AM_CXXFLAGS = @AM_CXXFLAGS@
