
file_list = \
pop_config.h \
pop.cc \
pop.h \
pop_paf.cc \
pop_paf.h \
pop_module.cc \
pop_module.h

# can't be linked dynamically yet
#if STATIC_INSPECTORS
noinst_LIBRARIES = libpop.a
libpop_a_SOURCES = $(file_list)
#else
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = pop.la
#pop_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#pop_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#pop_la_SOURCES = $(file_list)
#endif

