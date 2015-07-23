
selibdir = $(pkglibdir)/search_engines
selib_LTLIBRARIES = liblowmem.la
liblowmem_la_CXXFLAGS = $(AM_CXXFLAGS)
liblowmem_la_LDFLAGS = -export-dynamic -shared

liblowmem_la_SOURCES = \
lowmem.cc \
lowmem_q.cc \
pat_stats.cc \
sfksearch.cc \
sfksearch.h \
trie_api.cc

AM_CXXFLAGS = @AM_CXXFLAGS@

