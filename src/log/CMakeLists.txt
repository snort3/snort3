

set (LOG_INCLUDES
    messages.h
    text_log.h
)

add_library ( log STATIC
    ${LOG_INCLUDES}
    log.cc
    log.h
    log_text.cc
    log_text.h
    messages.cc
    text_log.cc
)

set_default_visibility_compile_flag(log)


install(FILES ${LOG_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/log"
)

target_link_libraries(log
    utils
    protocols
)
