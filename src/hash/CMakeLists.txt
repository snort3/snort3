
set (HASH_INCLUDES
    hashes.h
    ghash.h 
    xhash.h 
    hashfcn.h 
)

add_library( hash OBJECT
    ${HASH_INCLUDES}
    hashes.cc
    lru_cache_shared.h
    lru_cache_shared.cc
    ghash.cc 
    hashfcn.cc 
    primetable.cc 
    primetable.h 
    xhash.cc 
    zhash.cc 
    zhash.h
)

install(FILES ${HASH_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/hash"
)

add_subdirectory ( test )
