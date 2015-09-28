
if STATIC_CODECS
noinst_LIBRARIES = libroot_codecs.a

libroot_codecs_a_SOURCES = \
cd_eth.cc

else
ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = libcd_eth.la
libcd_eth_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libcd_eth_la_LDFLAGS = -export-dynamic -shared
libcd_eth_la_SOURCES =  cd_eth.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
