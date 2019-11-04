add_cpputest( ha_test )

add_cpputest( flow_stash_test
    SOURCES ../flow_stash.cc
)

add_cpputest( flow_control_test
    SOURCES ../flow_control.cc
)

add_cpputest( flow_cache_test
    SOURCES
        ../flow_cache.cc
        ../flow_control.cc
        ../flow_key.cc
        ../../hash/zhash.cc
        ../../hash/hashfcn.cc
        ../../hash/primetable.cc
)

add_cpputest( session_test )

add_cpputest( flow_test
    SOURCES ../flow.cc
)
