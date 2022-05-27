add_cpputest( lru_cache_local_test
    SOURCES ../lru_cache_local.h
)

add_cpputest( lru_cache_shared_test
    SOURCES ../lru_cache_shared.cc
)

add_cpputest( hash_lru_cache_test
    SOURCES ../hash_lru_cache.cc
)

add_cpputest( xhash_test
    SOURCES
        ../hash_key_operations.cc
        ../hash_lru_cache.cc
        ../primetable.cc
        ../xhash.cc
)

add_cpputest( ghash_test
    SOURCES
        ../ghash.cc
        ../hash_key_operations.cc
        ../hash_lru_cache.cc
        ../primetable.cc
)

add_cpputest( zhash_test
    SOURCES
        ../hash_key_operations.cc
        ../hash_lru_cache.cc
        ../primetable.cc
        ../xhash.cc
        ../zhash.cc
)
