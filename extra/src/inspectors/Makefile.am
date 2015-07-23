
insexlibdir = $(pkglibdir)/inspectors

insexlib_LTLIBRARIES = libdpx.la
libdpx_la_CXXFLAGS = $(AM_CXXFLAGS)
libdpx_la_LDFLAGS = -export-dynamic -shared
libdpx_la_SOURCES = dpx.cc

insexlib_LTLIBRARIES += libdata_log.la
libdata_log_la_CXXFLAGS = $(AM_CXXFLAGS)
libdata_log_la_LDFLAGS = -export-dynamic -shared
libdata_log_la_SOURCES = data_log.cc

AM_CXXFLAGS = @AM_CXXFLAGS@

