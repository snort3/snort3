
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
appid_http_event_test

TESTS = $(check_PROGRAMS)

appid_http_event_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

appid_http_event_test_LDADD = \
../appid_stats_counter.o \
@CPPUTEST_LDFLAGS@

