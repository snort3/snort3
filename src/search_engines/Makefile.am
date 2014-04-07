AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libsearch_engines.a

x_includedir = $(pkgincludedir)/search_engines

x_include_HEADERS = \
pat_stats.h

acsmx_sources = \
ac_std.cc \
acsmx.cc \
acsmx.h

acsmx2_sources = \
ac_banded.cc \
ac_full.cc \
ac_full_q.cc \
ac_sparse.cc \
ac_sparse_bands.cc \
acsmx2.cc \
acsmx2.h

bnfa_sources = \
ac_bnfa.cc \
ac_bnfa_q.cc \
bnfa_search.cc \
bnfa_search.h

if HAVE_INTEL_SOFT_CPM
intel_sources = \
intel_cpm.cc \
intel_soft_cpm.cc \
intel_soft_cpm.h
endif

plugin_list = \
$(acsmx_sources) \
$(acsmx2_sources) \
$(bnfa_sources) \
$(intel_sources)

libsearch_engines_a_SOURCES = \
search_engines.cc \
search_engines.h \
str_search.cc \
str_search.h

# FIXIT ideally don't include pat_stats.cc separately

if STATIC_SEARCH_ENGINES
libsearch_engines_a_SOURCES += $(plugin_list) pat_stats.cc
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

mpselib_LTLIBRARIES += libbnfa.la
libbnfa_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libbnfa_la_LDFLAGS = -export-dynamic -shared
libbnfa_la_SOURCES = $(bnfa_sources) bnfa_api.cc pat_stats.cc

mpselib_LTLIBRARIES += libintel_cpm.la
libintel_cpm_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libintel_cpm_la_LDFLAGS = -export-dynamic -shared
libintel_cpm_la_SOURCES = $(intel_sources) pat_stats.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

