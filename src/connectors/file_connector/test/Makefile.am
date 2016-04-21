
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
file_connector_test

TESTS = $(check_PROGRAMS)

file_connector_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

file_connector_test_LDADD = ../libfile_connector.a ../../../framework/libframework.a @CPPUTEST_LDFLAGS@

