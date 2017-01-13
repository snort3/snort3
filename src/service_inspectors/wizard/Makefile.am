
file_list = \
curses.cc \
curses.h \
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
shlib_LTLIBRARIES = wizard.la
wizard_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
wizard_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
wizard_la_SOURCES = $(file_list)
endif

