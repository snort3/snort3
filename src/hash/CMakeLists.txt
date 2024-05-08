
set (HASH_INCLUDES
    hashes.h
    hash_key_operations.h
    lru_cache_local.h
    lru_cache_shared.h
    lru_segmented_cache_shared.h
    xhash.h
)

add_library( hash OBJECT
    ${HASH_INCLUDES}
    ghash.cc
    ghash.h
    hash_defs.h
    hashes.cc
    hash_lru_cache.cc
    hash_lru_cache.h
    hash_key_operations.cc
    lru_cache_shared.cc
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
