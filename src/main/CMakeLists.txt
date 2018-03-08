
set (INCLUDES
    analyzer_command.h
    policy.h
    snort_config.h
    snort_debug.h
    snort_types.h
    thread.h
)

if ( ENABLE_DEBUG_MSGS )
    set ( DEBUG_MSGS_SOURCES snort_debug.cc )
endif ( ENABLE_DEBUG_MSGS )

if ( ENABLE_SHELL )
    set ( SHELL_SOURCES control.cc control.h control_mgmt.cc control_mgmt.h )
endif ( ENABLE_SHELL )

add_library (main OBJECT
    analyzer.cc
    analyzer.h
    analyzer_command.cc
    build.h
    help.cc
    help.h
    modules.cc
    modules.h
    policy.cc
    request.cc
    request.h
    shell.h
    shell.cc
    snort.cc
    snort.h
    snort_config.cc
    snort_module.h
    snort_module.cc
    swapper.cc
    swapper.h
    thread.cc
    thread_config.h
    thread_config.cc
    ${DEBUG_MSGS_SOURCES}
    ${INCLUDES}
    ${SHELL_SOURCES}
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/main"
)
