
set (LOG_INCLUDES
    messages.h
    text_log.h
    unified2.h
)

add_library ( log STATIC
    ${LOG_INCLUDES}
    log.cc
    log.h
    log_text.cc
    log_text.h
    messages.cc
    obfuscator.cc
    obfuscator.h
    packet_tracer.cc
    packet_tracer.h
    text_log.cc
)

install(FILES ${LOG_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/log"
)

target_link_libraries(log
    utils
    protocols
)

add_subdirectory ( test )
