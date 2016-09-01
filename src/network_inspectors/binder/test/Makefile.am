
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
binder_test

TESTS = $(check_PROGRAMS)

binder_test_CPPFLAGS = @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

binder_test_LDADD = \
../../../flow/libflow.a \
../../../framework/libframework.a \
../../../stream/libstream.a \
../../../stream/libstream_paf.a \
@CPPUTEST_LDFLAGS@

