
set (LOG_INCLUDES
    messages.h
    obfuscation.h
)

add_library ( log STATIC
    ${LOG_INCLUDES}
    log.cc 
    log.h 
    log_text.cc 
    log_text.h 
    messages.cc
    obfuscation.cc 
    obfuscation.h 
    sf_textlog.cc 
    sf_textlog.h
)

set_default_visibility_compile_flag( log )


install(FILES ${LOG_INCLUDES}
    DESTINATION "${CMAKE_PROJECT_NAME}/log"
)

target_link_libraries(log
    utils
)
