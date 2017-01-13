
if STATIC_CODECS
noinst_LIBRARIES = libroot_codecs.a

libroot_codecs_a_SOURCES = \
cd_eth.cc

else
ehlibdir = $(pkglibdir)/codecs

ehlib_LTLIBRARIES = cd_eth.la
cd_eth_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
cd_eth_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
cd_eth_la_SOURCES =  cd_eth.cc
endif
