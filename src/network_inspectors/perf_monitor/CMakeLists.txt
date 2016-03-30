
if( LINUX_SMP )
    set (PROCPIDSTATS_SOURCE
        proc_pid_stats.cc 
        proc_pid_stats.h
    )

endif(LINUX_SMP)

add_library ( perf_monitor STATIC
    base_tracker.cc
    base_tracker.h
    event_tracker.cc
    event_tracker.h
    flow_tracker.cc
    flow_tracker.h
    flow_ip_tracker.cc
    flow_ip_tracker.h
    perf_flow.cc
    perf_flow.h
    perf_module.cc
    perf_module.h
    perf_monitor.cc
    perf_monitor.h
    perf_tracker.cc
    perf_tracker.h
    ${PROCPIDSTATS_SOURCE}
)
