
noinst_LIBRARIES = libperf_monitor.a

if BUILD_PROCPIDSTATS
PROCPIDSTATS_SOURCE = \
sfprocpidstats.cc sfprocpidstats.h
endif

libperf_monitor_a_SOURCES = \
perf_monitor.cc perf_monitor.h \
perf_module.cc perf_module.h \
perf_tracker.cc perf_tracker.h \
base_tracker.cc base_tracker.h \
flow_tracker.cc flow_tracker.h \
flow_ip_tracker.cc flow_ip_tracker.h \
event_tracker.cc event_tracker.h \
perf_flow.cc perf_flow.h \
$(PROCPIDSTATS_SOURCE)

