
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
obfuscator_test

TESTS = $(check_PROGRAMS)

obfuscator_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@

obfuscator_test_LDADD = ../obfuscator.o \
						@CPPUTEST_LDFLAGS@

