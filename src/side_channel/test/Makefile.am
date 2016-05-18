
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
side_channel_test \
side_channel_module_test

TESTS = $(check_PROGRAMS)

side_channel_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
side_channel_module_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

side_channel_test_LDADD = \
../side_channel.o \
../../framework/libframework.a \
../../sfip/libsfip.a \
../../catch/libcatch_tests.a \
@CPPUTEST_LDFLAGS@

side_channel_module_test_LDADD = \
../side_channel_module.o \
../../framework/libframework.a \
../../sfip/libsfip.a \
../../catch/libcatch_tests.a \
@CPPUTEST_LDFLAGS@

