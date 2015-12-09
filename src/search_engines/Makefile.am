
noinst_LIBRARIES = libsearch_engines.a

x_includedir = $(pkgincludedir)/search_engines

x_include_HEADERS = \
pat_stats.h \
search_common.h

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
acsmx2.h

bnfa_sources = \
ac_bnfa.cc \
bnfa_search.cc \
bnfa_search.h

if HAVE_INTEL_SOFT_CPM
intel_sources = \
intel_cpm.cc \
intel_soft_cpm.cc \
intel_soft_cpm.h
endif

if HAVE_HYPERSCAN
hyper_sources = \
hyperscan.cc \
hyperscan.h
endif

plugin_list = \
$(acsmx_sources) \
$(acsmx2_sources) \
$(intel_sources) \
$(hyper_sources)

libsearch_engines_a_SOURCES = \
search_engines.cc \
search_engines.h \
search_tool.cc \
search_tool.h \
pat_stats.cc \
$(bnfa_sources)

# FIXIT ideally don't include pat_stats.cc separately

if STATIC_SEARCH_ENGINES
libsearch_engines_a_SOURCES += $(plugin_list)
else
mpselibdir = $(pkglibdir)/search_engines

mpselib_LTLIBRARIES = libacsmx.la
libacsmx_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libacsmx_la_LDFLAGS = -export-dynamic -shared
libacsmx_la_SOURCES = $(acsmx_sources) pat_stats.cc

mpselib_LTLIBRARIES += libacsmx2.la
libacsmx2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libacsmx2_la_LDFLAGS = -export-dynamic -shared
libacsmx2_la_SOURCES = $(acsmx2_sources) acsmx2_api.cc pat_stats.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

# FIXIT-H new profiler dependencies break link but
# resolving those leads to duplicate symbols for new,
# new[], delete, and delete[].
#if BUILD_CPPUTESTS
#SUBDIRS = test
#endif

