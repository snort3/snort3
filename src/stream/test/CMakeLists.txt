
add_cpputest( stream_splitter_test
    SOURCES
    ../stream_splitter.cc
)

add_cpputest( ip_frag_tracker_test )

add_cpputest( stream_ha_test
    SOURCES
    ../base/stream_ha.cc
)

add_cpputest( user_session_test
    SOURCES
    ../user/user_session.cc
    ../stream_splitter.cc
)
