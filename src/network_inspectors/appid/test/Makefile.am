
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
appid_http_event_test \
appid_api_test \
appid_detector_test \
app_info_table_test

TESTS = $(check_PROGRAMS)

appid_http_event_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

appid_http_event_test_LDADD = \
../appid_stats_counter.o \
../../../sfip/sf_ip.o \
@CPPUTEST_LDFLAGS@

appid_api_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

appid_api_test_LDADD = \
../appid_stats_counter.o \
../../../sfip/sf_ip.o \
@CPPUTEST_LDFLAGS@

app_info_table_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
app_info_table_test_LDADD = \
../appid_stats_counter.o \
@CPPUTEST_LDFLAGS@

appid_detector_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@
appid_detector_test_LDADD = \
../appid_stats_counter.o \
../../../sfip/sf_ip.o \
@CPPUTEST_LDFLAGS@

