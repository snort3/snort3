
cdlibdir = $(pkglibdir)/codecs

cdlib_LTLIBRARIES = libpim.la
libpim_la_CXXFLAGS = $(AM_CXXFLAGS)
libpim_la_LDFLAGS = -export-dynamic -shared
libpim_la_SOURCES = pim.cc

cdlib_LTLIBRARIES += libtoken_ring.la
libtoken_ring_la_CXXFLAGS = $(AM_CXXFLAGS)
libtoken_ring_la_LDFLAGS = -export-dynamic -shared
libtoken_ring_la_SOURCES = token_ring.cc

cdlib_LTLIBRARIES += libsocket.la
libsocket_la_CXXFLAGS = $(AM_CXXFLAGS)
libsocket_la_LDFLAGS = -export-dynamic -shared
libsocket_la_SOURCES = socket.cc

AM_CXXFLAGS = @AM_CXXFLAGS@

