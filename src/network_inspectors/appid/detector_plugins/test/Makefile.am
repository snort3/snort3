
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
detector_smtp_test \
http_url_patterns_test

TESTS = $(check_PROGRAMS)

detector_smtp_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

detector_smtp_test_LDADD = \
../../../../utils/libutils.a \
@CPPUTEST_LDFLAGS@

http_url_patterns_test_CPPFLAGS = -I$(top_srcdir)/src/network_inspectors/appid @AM_CPPFLAGS@ @CPPUTEST_CPPFLAGS@

http_url_patterns_test_LDADD = \
../../../../utils/libutils.a \
@CPPUTEST_LDFLAGS@

