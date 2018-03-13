if ( FLATBUFFERS_FOUND )
    set( FLATBUFFERS_SOURCE fbs_formatter.h fbs_formatter.cc )
endif()

add_library ( perf_monitor OBJECT
    base_tracker.cc
    base_tracker.h
    csv_formatter.cc
    csv_formatter.h
    cpu_tracker.cc
    cpu_tracker.h
    ${FLATBUFFERS_SOURCE}
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
    perf_tracker.cc
    perf_tracker.h
    text_formatter.cc
    text_formatter.h
)

if ( FLATBUFFERS_FOUND )
    target_include_directories( perf_monitor PRIVATE ${FLATBUFFERS_INCLUDE_DIR} )
endif()
