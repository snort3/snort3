set ( MEMORY_SOURCES
    memory_allocator.cc
    memory_cap.cc
    memory_manager.cc
    )

add_library ( memory STATIC
    ${MEMORY_SOURCES}
)
