
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
tcp_connector_test \
tcp_connector_module_test

TESTS = $(check_PROGRAMS)

tcp_connector_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
tcp_connector_test_LDADD = \
../tcp_connector.o \
../../../framework/libframework.a \
@CPPUTEST_LDFLAGS@

tcp_connector_module_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
tcp_connector_module_test_LDADD = \
../tcp_connector_module.o \
../../../framework/libframework.a \
../../../sfip/libsfip.a \
../../../catch/libcatch_tests.a \
@CPPUTEST_LDFLAGS@

