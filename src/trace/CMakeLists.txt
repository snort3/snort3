
set ( TRACE_SOURCES
    trace_config.cc
    trace_config.h
    trace_log.cc
    trace_log.h
    trace_log_api.cc
    trace_log_api.h
    trace_log_base.h
    trace_module.cc
    trace_module.h
)

add_library ( trace OBJECT
    ${TRACE_SOURCES}
)
