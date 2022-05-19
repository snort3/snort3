
set ( FILE_LIST
    base_tracker.cc
    base_tracker.h
    csv_formatter.cc
    csv_formatter.h
    cpu_tracker.cc
    cpu_tracker.h
    flow_tracker.cc
    flow_tracker.h
    flow_ip_tracker.cc
    flow_ip_tracker.h
    json_formatter.cc
    json_formatter.h
    perf_formatter.cc
    perf_formatter.h
    perf_module.cc
    perf_module.h
    perf_monitor.cc
    perf_pegs.h
    perf_reload_tuner.h
    perf_tracker.cc
    perf_tracker.h
    text_formatter.cc
    text_formatter.h
)

if (STATIC_INSPECTORS)
    add_library(perf_monitor OBJECT
        ${FILE_LIST}
    )

else (STATIC_INSPECTORS)
    add_dynamic_module(perf_monitor inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

add_catch_test( csv_formatter_test
    NO_TEST_SOURCE
    SOURCES
        csv_formatter.cc
        perf_formatter.cc
)

add_catch_test( json_formatter_test
    NO_TEST_SOURCE
    SOURCES
        json_formatter.cc
        perf_formatter.cc
)

