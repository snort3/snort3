
set (INCLUDES
    thread.h
    snort_debug.h
    snort_types.h
)

add_library (main STATIC
    analyzer.h
    analyzer.cc 
    build.h
    modules.cc
    modules.h
    policy.h
    policy.cc
    shell.h
    shell.cc
    snort.h
    snort.cc
    snort_debug.cc
    snort_config.h
    snort_config.cc
    thread.cc 
	${INCLUDES}
)


target_link_libraries(main
    time
    codecs
    detection
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/main"
)
