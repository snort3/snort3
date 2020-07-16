set ( INCLUDES
    trace.h
    trace_api.h
    trace_logger.h
)

set ( TRACE_SOURCES
    trace.cc
    trace_api.cc
    trace_config.cc
    trace_config.h
    trace_loggers.cc
    trace_loggers.h
    trace_module.cc
    trace_module.h
    trace_parser.cc
    trace_parser.h
    trace_swap.cc
    trace_swap.h
    ${INCLUDES}
)

add_library ( trace OBJECT
    ${TRACE_SOURCES}
)

install ( FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/trace"
)

add_catch_test( trace_test
    NO_TEST_SOURCE
    SOURCES
        trace.cc
)

