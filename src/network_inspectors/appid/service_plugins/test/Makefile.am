
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
service_rsync_test

TESTS = $(check_PROGRAMS)

service_rsync_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
service_rsync_test_LDADD = \
../../appid_stats_counter.o \
@CPPUTEST_LDFLAGS@

