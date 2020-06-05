
set (INCLUDES
    analyzer_command.h
    policy.h
    snort.h
    snort_config.h
    snort_debug.h
    snort_types.h
    thread.h
)

if ( ENABLE_SHELL )
    set ( SHELL_SOURCES control.cc control.h control_mgmt.cc control_mgmt.h ac_shell_cmd.h ac_shell_cmd.cc)
endif ( ENABLE_SHELL )

add_subdirectory(test)

add_library (main OBJECT
    analyzer.cc
    analyzer.h
    analyzer_command.cc
    build.h
    help.cc
    help.h
    modules.cc
    modules.h
    oops_handler.cc
    oops_handler.h
    policy.cc
    request.cc
    request.h
    shell.h
    shell.cc
    snort.cc
    snort.h
    snort_config.cc
    snort_debug.cc
    snort_module.h
    snort_module.cc
    swapper.cc
    swapper.h
    thread.cc
    thread_config.h
    thread_config.cc
    ${INCLUDES}
    ${SHELL_SOURCES}
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/main"
)
