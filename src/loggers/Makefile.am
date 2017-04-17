
noinst_LIBRARIES = libloggers.a
libloggers_a_SOURCES = \
alert_luajit.cc \
alert_sf_socket.cc \
log_codecs.cc \
loggers.cc \
loggers.h

plugin_list = \
alert_csv.cc \
alert_fast.cc \
alert_full.cc \
alert_syslog.cc \
log_hext.cc \
log_pcap.cc \
unified2.cc

if STATIC_LOGGERS
libloggers_a_SOURCES += $(plugin_list)

else
ehlibdir = $(pkglibdir)/loggers

ehlib_LTLIBRARIES = alert_csv.la
alert_csv_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
alert_csv_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
alert_csv_la_SOURCES = alert_csv.cc

ehlib_LTLIBRARIES += alert_fast.la
alert_fast_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
alert_fast_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
alert_fast_la_SOURCES = alert_fast.cc

ehlib_LTLIBRARIES += alert_full.la
alert_full_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
alert_full_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
alert_full_la_SOURCES = alert_full.cc

ehlib_LTLIBRARIES += alert_syslog.la
alert_syslog_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
alert_syslog_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
alert_syslog_la_SOURCES = alert_syslog.cc

ehlib_LTLIBRARIES += log_hext.la
log_hext_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
log_hext_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
log_hext_la_SOURCES = log_hext.cc

ehlib_LTLIBRARIES += log_pcap.la
log_pcap_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
log_pcap_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
log_pcap_la_SOURCES = log_pcap.cc

ehlib_LTLIBRARIES += unified2.la
unified2_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
unified2_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
unified2_la_SOURCES = unified2.cc
endif

