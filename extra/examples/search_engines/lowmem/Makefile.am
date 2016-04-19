AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

lowmemlibdir = $(pkglibdir)/search_engines

lowmemlib_LTLIBRARIES = liblowmem.la
liblowmem_la_CXXFLAGS = $(AM_CXXFLAGS)
liblowmem_la_LDFLAGS = -export-dynamic -shared
liblowmem_la_SOURCES = lowmem.cc sfksearch.cc trie_api.cc
