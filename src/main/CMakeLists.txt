
set (INCLUDES
    policy.h
    snort_config.h
    snort_debug.h
    snort_types.h
    thread.h
)

if ( ENABLE_DEBUG_MSGS )
    set ( DEBUG_MSGS_SOURCES snort_debug.cc )
endif ( ENABLE_DEBUG_MSGS )

add_library (main STATIC
    analyzer.h
    analyzer.cc 
    build.h
    help.cc
    help.h
    modules.cc
    modules.h
    policy.cc
    shell.h
    shell.cc
    snort.cc
    snort.h
    ${DEBUG_MSGS_SOURCES}
    snort_config.cc
    snort_module.h
    snort_module.cc
    thread.cc
    thread_config.h
    thread_config.cc
    ${INCLUDES}
)


target_link_libraries(main
    time
    codecs
    detection
    packet_io
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/main"
)
