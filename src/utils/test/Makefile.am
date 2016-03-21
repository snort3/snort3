
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
util_math_test

TESTS = $(check_PROGRAMS)

util_math_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
util_math_test_LDADD = ../util_math.o @CPPUTEST_LDFLAGS@

