
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
search_tool_test

TESTS = $(check_PROGRAMS)

search_tool_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
search_tool_test_LDADD = \
../libsearch_engines.a \
../../catch/unit_test.o \
@CPPUTEST_LDFLAGS@

if HAVE_HYPERSCAN
check_PROGRAMS += hyperscan_test

hyperscan_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@

hyperscan_test_LDADD = \
../hyperscan.o \
../../catch/unit_test.o \
@CPPUTEST_LDFLAGS@
endif

