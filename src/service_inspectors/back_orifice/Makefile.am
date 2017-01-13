
file_list = \
back_orifice.cc

if STATIC_INSPECTORS
noinst_LIBRARIES = libback_orifice.a
libback_orifice_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = back_orifice.la
back_orifice_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
back_orifice_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
back_orifice_la_SOURCES = $(file_list)
endif

