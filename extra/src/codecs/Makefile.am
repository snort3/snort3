AUTOMAKE_OPTIONS=foreign

ehlibdir = $(pkglibdir)/codecs
ehlib_LTLIBRARIES = libpim.la
libpim_la_CXXFLAGS = $(AM_CXXFLAGS)
libpim_la_LDFLAGS = -export-dynamic -shared
libpim_la_SOURCES = pim.cc


ehlib_LTLIBRARIES += libtoken_ring.la
libtoken_ring_la_CXXFLAGS = $(AM_CXXFLAGS)
libtoken_ring_la_LDFLAGS = -export-dynamic -shared
libtoken_ring_la_SOURCES = token_ring.cc

AM_CXXFLAGS = @AM_CXXFLAGS@
