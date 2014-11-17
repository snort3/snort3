
set (INCLUDES
    thread.h
    snort_debug.h
    snort_types.h
    snort.h
    snort_config.h
    policy.h
)

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
    snort.h
    snort.cc
    snort_debug.cc
    snort_config.cc
    snort_module.h
    snort_module.cc
    thread.cc 
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
