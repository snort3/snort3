
include_directories( ../../../network_inspectors ${LUAJIT_INCLUDE_DIR} )

set (
    STREAM_TCP_TEST_SOURCES
    ../tcp_normalizer.cc
    ../tcp_normalizers.cc
    ../../../protocols/tcp_options.cc
)

if ( ENABLE_DEBUG_MSGS )
    list (
        APPEND STREAM_TCP_TEST_SOURCES
        ../../../main/snort_debug.cc
    )
endif ( ENABLE_DEBUG_MSGS )

add_library ( stream_tcp_test ${STREAM_TCP_TEST_SOURCES} )

# this test is broken, uncomment below when fixed
# add_cpputest( tcp_normalizer_test stream_tcp_test )
