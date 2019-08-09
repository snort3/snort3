add_cpputest( lru_cache_shared_test
    SOURCES ../lru_cache_shared.cc
)

add_cpputest( xhash_test
    SOURCES
        ../xhash.cc
        ../hashfcn.cc
        ../primetable.cc
        ../../utils/sfmemcap.cc
)

add_cpputest( ghash_test
    SOURCES
        ../ghash.cc
        ../hashfcn.cc
        ../primetable.cc
)
