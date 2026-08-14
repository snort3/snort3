add_cpputest( ha_test
    SOURCES flow_stubs.h
)

add_cpputest( deferred_trust_test
    SOURCES ../deferred_trust.cc
)

add_cpputest( flow_stash_test
    SOURCES ../flow_stash.cc
            ../../sfip/sf_ip.cc
)

add_cpputest( flow_control_test
    SOURCES ../flow_control.cc
            flow_stubs.h
)

add_cpputest( flow_cache_test
    SOURCES
        ../deferred_trust.cc
        ../dump_flows.cc
        ../dump_flows_serializer.cc
        ../flow_cache.cc
        ../flow_control.cc
        ../flow_key.cc
        flow_stubs.h
        ../../hash/hash_key_operations.cc
        ../../hash/hash_lru_cache.cc
        ../../hash/primetable.cc
        ../../hash/xhash.cc
        ../../hash/zhash.cc
)

add_cpputest( session_test )

add_cpputest( flow_test
    SOURCES
        ../flow.cc
        ../flow_data.cc
        ../flow_stash.cc
        flow_stubs.h
        ../../sfip/sf_ip.cc
)
