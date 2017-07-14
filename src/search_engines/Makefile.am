
noinst_LIBRARIES = libsearch_engines.a

x_includedir = $(pkgincludedir)/search_engines

x_include_HEADERS = \
search_common.h \
search_tool.h

acsmx_sources = \
ac_std.cc \
acsmx.cc \
acsmx.h

acsmx2_sources = \
ac_banded.cc \
ac_full.cc \
ac_sparse.cc \
ac_sparse_bands.cc \
acsmx2.cc \
acsmx2.h \
acsmx2_api.cc

bnfa_sources = \
ac_bnfa.cc \
bnfa_search.cc \
bnfa_search.h

if HAVE_HYPERSCAN
hyper_sources = \
hyperscan.cc \
hyperscan.h
endif

plugin_list = \
$(acsmx_sources) \
$(acsmx2_sources) \
$(intel_sources)

libsearch_engines_a_SOURCES = \
pat_stats.h \
search_engines.cc \
search_engines.h \
search_tool.cc \
$(bnfa_sources) \
$(hyper_sources)

if STATIC_SEARCH_ENGINES
libsearch_engines_a_SOURCES += $(plugin_list)
else
mpselibdir = $(pkglibdir)/search_engines

mpselib_LTLIBRARIES = acsmx.la
acsmx_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
acsmx_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
acsmx_la_SOURCES = $(acsmx_sources)

mpselib_LTLIBRARIES += acsmx2.la
acsmx2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
acsmx2_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
acsmx2_la_SOURCES = $(acsmx2_sources)
endif

if BUILD_CPPUTESTS
SUBDIRS = test
endif

