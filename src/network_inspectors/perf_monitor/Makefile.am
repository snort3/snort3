
noinst_LIBRARIES = libperf_monitor.a

libperf_monitor_a_SOURCES = \
base_tracker.cc base_tracker.h \
csv_formatter.cc csv_formatter.h \
cpu_tracker.cc cpu_tracker.h \
flow_tracker.cc flow_tracker.h \
flow_ip_tracker.cc flow_ip_tracker.h \
json_formatter.cc json_formatter.h \
perf_formatter.cc perf_formatter.h \
perf_monitor.cc perf_monitor.h \
perf_module.cc perf_module.h \
perf_tracker.cc perf_tracker.h \
text_formatter.cc text_formatter.h

if HAVE_FLATBUFFERS
libperf_monitor_a_SOURCES += fbs_formatter.cc fbs_formatter.h
endif
