
AM_DEFAULT_SOURCE_EXT = .cc

if HAVE_HYPERSCAN
check_PROGRAMS = \
hyperscan_test

TESTS = $(check_PROGRAMS)

hyperscan_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

hyperscan_test_LDADD = \
../hyperscan.o \
../../catch/unit_test.o \
@CPPUTEST_LDFLAGS@
endif

