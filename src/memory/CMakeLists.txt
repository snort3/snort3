set ( MEMORY_SOURCES
    memory_cap.cc
    memory_cap.h
    memory_module.cc
    memory_module.h
    memory_config.h
    prune_handler.cc
    prune_handler.h
)

add_library ( memory OBJECT
    ${MEMORY_SOURCES}
)
