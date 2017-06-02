
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
stream_splitter_test

TESTS = $(check_PROGRAMS)

stream_splitter_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@

stream_splitter_test_LDADD = \
../stream_splitter.o \
@CPPUTEST_LDFLAGS@

