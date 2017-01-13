lowmemlibdir = $(pkglibdir)/search_engines

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

lowmemlib_LTLIBRARIES = lowmem.la
lowmem_la_CXXFLAGS = $(AM_CXXFLAGS)
lowmem_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
lowmem_la_SOURCES  = lowmem.cc sfksearch.cc sfksearch.h trie_api.cc
