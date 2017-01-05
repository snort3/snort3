
set (HASH_INCLUDES
    hashes.h
    sfghash.h 
    sfxhash.h 
    sfhashfcn.h 
)

set (HASH_SOURCES )

add_library( hash STATIC
    ${HASH_INCLUDES}
    ${HASH_SOURCES}
    hashes.cc
    lru_cache_shared.h
    lru_cache_shared.cc
    sfghash.cc 
    sfhashfcn.cc 
    sfprimetable.cc 
    sfprimetable.h 
    sfxhash.cc 
    zhash.cc 
    zhash.h
)

install(FILES ${HASH_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/hash"
)

add_subdirectory ( test )
