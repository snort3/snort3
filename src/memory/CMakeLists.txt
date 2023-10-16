set (MEMCAP_INCLUDES
    heap_interface.h
    memory_cap.h
)

set ( MEMORY_SOURCES
    ${MEMCAP_INCLUDES}
    heap_interface.cc
    memory_cap.cc
    memory_config.h
    memory_module.cc
    memory_module.h
    memory_overloads.cc
)

set ( ALLOC_SOURCES
    memory_allocator.cc
    memory_allocator.h
)

if ( ENABLE_MEMORY_PROFILER )
    list ( APPEND MEMORY_SOURCES ${ALLOC_SOURCES} )
endif ()

add_library ( memory OBJECT
    ${MEMORY_SOURCES}
)

install(FILES ${MEMCAP_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/memory/"
)

add_subdirectory(test)

