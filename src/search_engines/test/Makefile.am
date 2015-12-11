
AM_DEFAULT_SOURCE_EXT = .cc

if BUILD_CPPUTESTS
# FIXIT-H new profiler dependencies break link but resolving those leads to
# duplicate symbols for new, new[], delete, and delete[].  this if disables
# these tests until they are fixed.
else

if HAVE_HYPERSCAN
check_PROGRAMS = \
hyperscan_test

TESTS = $(check_PROGRAMS)

hyperscan_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

hyperscan_test_LDADD = \
../hyperscan.o \
../../catch/unit_test.o \
../../framework/mpse.o \
@CPPUTEST_LDFLAGS@
endif

endif

