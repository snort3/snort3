lowmemlibdir = $(pkglibdir)/search_engines

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

lowmemlib_LTLIBRARIES = liblowmem.la
liblowmem_la_CXXFLAGS = $(AM_CXXFLAGS)
liblowmem_la_LDFLAGS  = -export-dynamic -shared -avoid-version
liblowmem_la_SOURCES  = lowmem.cc sfksearch.cc sfksearch.h trie_api.cc
