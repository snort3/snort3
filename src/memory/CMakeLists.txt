set (MEMCAP_INCLUDES
    memory_cap.h
)

set ( MEMORY_SOURCES
    ${MEMCAP_INCLUDES}
    memory_cap.cc
    memory_module.cc
    memory_module.h
    memory_config.h
    prune_handler.cc
    prune_handler.h
)

add_library ( memory OBJECT
    ${MEMORY_SOURCES}
)

install(FILES ${MEMCAP_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/memory/"
)
