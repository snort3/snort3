
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
side_channel_test

TESTS = $(check_PROGRAMS)

side_channel_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

side_channel_test_LDADD = ../../framework/libframework.a ../../sfip/libsfip.a ../../catch/libcatch_tests.a @CPPUTEST_LDFLAGS@

