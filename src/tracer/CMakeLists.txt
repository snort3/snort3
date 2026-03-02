
SET( PLUGIN_LIST
    file_trace_logger.cc
    file_trace_logger.h
    stdout_trace_logger.cc
    stdout_trace_logger.h
    syslog_trace_logger.cc
    syslog_trace_logger.h
)

set (TRACER_SOURCES
    trace_loader.cc
    trace_loader.h
)

if (STATIC_TRACERS)

    add_library ( tracer OBJECT
        ${TRACER_SOURCES}
        ${PLUGIN_LIST}
    )

else (STATIC_TRACERS)

    add_library ( tracer OBJECT
        ${TRACER_SOURCES}
    )

    add_dynamic_module(file_trace_logger tracer file_trace_logger.cc file_trace_logger.h)
    add_dynamic_module(stdout_trace_logger tracer stdout_trace_logger.cc stdout_trace_logger.h)
    add_dynamic_module(syslog_trace_logger tracer syslog_trace_logger.cc syslog_trace_logger.h)

endif (STATIC_TRACERS)

