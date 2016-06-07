
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
ha_test \
ha_module_test

TESTS = $(check_PROGRAMS)

ha_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
ha_module_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

ha_test_LDADD = \
../ha.o \
@CPPUTEST_LDFLAGS@

ha_module_test_LDADD = \
../ha_module.o \
../../framework/libframework.a \
../../sfip/libsfip.a \
../../catch/libcatch_tests.a \
@CPPUTEST_LDFLAGS@

