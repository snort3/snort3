
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
host_tracker_module_test \
host_cache_module_test \
host_cache_test \
host_tracker_test

TESTS = $(check_PROGRAMS)

host_cache_module_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
host_tracker_module_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
host_cache_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
host_tracker_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@

host_cache_module_test_LDADD = ../host_cache_module.o ../host_cache.o ../host_tracker.o ../../framework/libframework.a ../../catch/libcatch_tests.a ../../sfip/libsfip.a ../../hash/libhash.a @CPPUTEST_LDFLAGS@
host_tracker_module_test_LDADD = ../host_tracker_module.o ../host_cache.o ../host_tracker.o ../../framework/libframework.a ../../catch/libcatch_tests.a ../../sfip/libsfip.a @CPPUTEST_LDFLAGS@
host_cache_test_LDADD = ../host_cache.o ../host_tracker.o ../../sfip/libsfip.a @CPPUTEST_LDFLAGS@
host_tracker_test_LDADD = ../host_tracker.o ../../sfip/libsfip.a @CPPUTEST_LDFLAGS@

