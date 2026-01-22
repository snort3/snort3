add_library( tracer OBJECT
    trace_loader.cc
    trace_loader.h
    stdout_trace_logger.cc
    stdout_trace_logger.h
    syslog_trace_logger.h
    syslog_trace_logger.cc
    file_trace_logger.cc
    file_trace_logger.h
)

add_catch_test( stdout_tracer_test
    NO_TEST_SOURCE
    SOURCES
        stdout_trace_logger.cc
)

add_catch_test( syslog_tracer_test
    NO_TEST_SOURCE
    SOURCES
        syslog_trace_logger.cc
)

add_catch_test( file_tracer_test
    NO_TEST_SOURCE
    SOURCES
        file_trace_logger.cc
)
