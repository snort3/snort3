
file_list = \
magic.cc magic.h \
hexes.cc \
spells.cc \
wizard.cc \
wiz_module.cc wiz_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libwizard.a
libwizard_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libwizard.la
libwizard_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libwizard_la_LDFLAGS = -export-dynamic -shared
libwizard_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

