
file_list = \
pop_config.h \
pop.cc \
pop.h \
pop_paf.cc \
pop_paf.h \
pop_module.cc \
pop_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libpop.a
libpop_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libpop.la
libpop_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpop_la_LDFLAGS = -export-dynamic -shared
libpop_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

