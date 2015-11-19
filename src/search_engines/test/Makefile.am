AM_DEFAULT_SOURCE_EXT = .cc

if HAVE_HYPERSCAN
check_PROGRAMS = \
hyperscan_test

TESTS = $(check_PROGRAMS)

hyperscan_test_LDADD = \
../hyperscan.o \
../../catch/unit_test.o \
../../framework/mpse.o
endif

