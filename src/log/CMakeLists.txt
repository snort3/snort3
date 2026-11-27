
set (LOG_INCLUDES
    log_stats.h
    log_text.h
    messages.h
    num_format.h
    obfuscator.h
    text_log.h
    unified2.h
    u2_packet.h
)

add_library ( log OBJECT
    ${LOG_INCLUDES}
    batched_logger.cc
    batched_logger.h
    log.cc
    log.h
    log_errors.h
    log_stats.cc
    log_text.cc
    messages.cc
    num_format.cc
    obfuscator.cc
    text_log.cc
    u2_packet.cc
)

install(FILES ${LOG_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/log"
)

add_catch_test( num_format_test
    NO_TEST_SOURCE
    SOURCES
        num_format.cc
)

add_subdirectory ( test )
