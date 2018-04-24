
set (LOG_INCLUDES
    log.h
    log_text.h
    messages.h
    obfuscator.h
    text_log.h
    unified2.h
    u2_packet.h
)

add_library ( log OBJECT
    ${LOG_INCLUDES}
    log.cc
    log_text.cc
    messages.cc
    obfuscator.cc
    text_log.cc
    u2_packet.cc
)

install(FILES ${LOG_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/log"
)

add_subdirectory ( test )
