
AM_CPPFLAGS+=-I$(top_srcdir)/src/network_inspectors/appid

file_list = \
detector_api.h \
detector_base.cc \
detector_base.h \
detector_dns.cc \
detector_dns.h \
detector_http.cc \
detector_http.h \
detector_imap.cc \
detector_kerberos.cc \
detector_pattern.cc \
detector_pattern.h \
detector_pop3.cc \
detector_sip.cc \
detector_sip.h \
http_url_patterns.cc \
http_url_patterns.h

noinst_LIBRARIES = libappid_detector_plugins.a
libappid_detector_plugins_a_SOURCES = $(file_list)

#  Uncomment once tests are ready.
#if BUILD_UNIT_TESTS
#SUBDIRS = test
#endif


