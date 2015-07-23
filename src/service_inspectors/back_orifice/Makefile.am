
file_list = \
back_orifice.cc

if STATIC_INSPECTORS
noinst_LIBRARIES = libback_orifice.a
libback_orifice_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libback_orifice.la
libback_orifice_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libback_orifice_la_LDFLAGS = -export-dynamic -shared
libback_orifice_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

