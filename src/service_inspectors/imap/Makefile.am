
file_list = \
imap_config.h \
imap.cc \
imap.h \
imap_paf.cc \
imap_paf.h \
imap_module.cc \
imap_module.h

# can't be linked dynamically yet
#if STATIC_INSPECTORS
noinst_LIBRARIES = libimap.a
libimap_a_SOURCES = $(file_list)
#else
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = imap.la
#imap_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#imap_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#imap_la_SOURCES = $(file_list)
#endif

