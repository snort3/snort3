

if( BUILD_PROCPIDSTATS )
    set (PROCPIDSTATS_SOURCE
        sfprocpidstats.cc 
        sfprocpidstats.h
    )

endif()


add_library ( perf_monitor STATIC
    perf_monitor.cc
    perf_module.cc
    perf_module.h
    perf_base.cc
    perf_base.h
    perf_event.cc
    perf_event.h
    perf_flow.cc
    perf_flow.h
    perf.cc
    perf.h
    ${PROCPIDSTATS_SOURCE}
)
