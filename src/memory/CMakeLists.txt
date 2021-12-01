set (MEMCAP_INCLUDES
    memory_cap.h
)

set ( MEMORY_SOURCES
    ${MEMCAP_INCLUDES}
    memory_allocator.cc
    memory_allocator.h
    memory_cap.cc
    memory_config.h
    memory_manager.cc
    memory_module.cc
    memory_module.h
    prune_handler.cc
    prune_handler.h
)

add_library ( memory OBJECT
    ${MEMORY_SOURCES}
)

install(FILES ${MEMCAP_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/memory/"
)
