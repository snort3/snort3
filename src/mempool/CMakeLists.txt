
set (MEMPOOL_INCLUDES
    mempool.h 
    sf_sdlist_types.h
)

add_library ( mempool STATIC
    mempool.cc 
    sf_sdlist.cc 
    sf_sdlist.h 
)


install(FILES ${MEMPOOL_INCLUDES}
    DESTINATION "${CMAKE_PROJECT_NAME}/mempool"
)

