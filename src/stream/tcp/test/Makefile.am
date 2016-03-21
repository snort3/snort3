
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
tcp_normalizer_test

TESTS = $(check_PROGRAMS)

tcp_normalizer_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@

tcp_normalizer_test_LDADD = \
../tcp_normalizer.o \
../tcp_normalizers.o \
../../../protocols/tcp_options.o \
../../../main/snort_debug.o \
@CPPUTEST_LDFLAGS@

