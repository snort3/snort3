
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
lru_cache_shared_test \
ghash_test

TESTS = $(check_PROGRAMS)

lru_cache_shared_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
lru_cache_shared_test_LDADD = ../lru_cache_shared.o @CPPUTEST_LDFLAGS@

ghash_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
ghash_test_LDADD = ../libhash.a @CPPUTEST_LDFLAGS@
