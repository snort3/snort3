
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
file_connector_test \
file_connector_module_test

TESTS = $(check_PROGRAMS)

file_connector_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
file_connector_test_LDADD = \
../file_connector.o \
../../../framework/libframework.a \
@CPPUTEST_LDFLAGS@

file_connector_module_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
file_connector_module_test_LDADD = \
../file_connector_module.o \
../../../framework/libframework.a \
../../../sfip/libsfip.a \
../../../catch/libcatch_tests.a \
@CPPUTEST_LDFLAGS@

