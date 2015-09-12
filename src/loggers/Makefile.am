
noinst_LIBRARIES = libloggers.a
libloggers_a_SOURCES = \
alert_luajit.cc \
log_codecs.cc \
loggers.cc \
loggers.h

plugin_list = \
alert_csv.cc \
alert_fast.cc \
alert_full.cc \
alert_syslog.cc \
alert_unixsock.cc \
log_hext.cc \
log_null.cc \
log_pcap.cc \
unified2.cc \
unified2_common.h

if LINUX
libloggers_a_SOURCES += alert_sf_socket.cc
endif

if STATIC_LOGGERS
libloggers_a_SOURCES += $(plugin_list)

else
ehlibdir = $(pkglibdir)/loggers

ehlib_LTLIBRARIES = libalert_csv.la
libalert_csv_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libalert_csv_la_LDFLAGS = -export-dynamic -shared
libalert_csv_la_SOURCES = alert_csv.cc

ehlib_LTLIBRARIES += libalert_fast.la
libalert_fast_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libalert_fast_la_LDFLAGS = -export-dynamic -shared
libalert_fast_la_SOURCES = alert_fast.cc

ehlib_LTLIBRARIES += libalert_full.la
libalert_full_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libalert_full_la_LDFLAGS = -export-dynamic -shared
libalert_full_la_SOURCES = alert_full.cc

ehlib_LTLIBRARIES += libalert_syslog.la
libalert_syslog_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libalert_syslog_la_LDFLAGS = -export-dynamic -shared
libalert_syslog_la_SOURCES = alert_syslog.cc

ehlib_LTLIBRARIES += libalert_unixsock.la
libalert_unixsock_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libalert_unixsock_la_LDFLAGS = -export-dynamic -shared
libalert_unixsock_la_SOURCES = alert_unixsock.cc

ehlib_LTLIBRARIES += liblog_hext.la
liblog_hext_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
liblog_hext_la_LDFLAGS = -export-dynamic -shared
liblog_hext_la_SOURCES = log_hext.cc

ehlib_LTLIBRARIES += liblog_null.la
liblog_null_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
liblog_null_la_LDFLAGS = -export-dynamic -shared
liblog_null_la_SOURCES = log_null.cc

ehlib_LTLIBRARIES += liblog_pcap.la
liblog_pcap_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
liblog_pcap_la_LDFLAGS = -export-dynamic -shared
liblog_pcap_la_SOURCES = log_pcap.cc

ehlib_LTLIBRARIES += libunified2.la
libunified2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libunified2_la_LDFLAGS = -export-dynamic -shared
libunified2_la_SOURCES = unified2.cc unified2_common.h
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

