
AM_DEFAULT_SOURCE_EXT = .cc

if HAVE_HYPERSCAN
check_PROGRAMS = \
ips_regex_test

TESTS = $(check_PROGRAMS)

ips_regex_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@

ips_regex_test_LDADD = \
../ips_regex.o \
../../catch/unit_test.o \
../../framework/ips_option.o \
../../framework/module.o \
../../framework/value.o \
../../sfip/sf_ip.o \
../../sfip/sf_cidr.o \
@CPPUTEST_LDFLAGS@
endif

