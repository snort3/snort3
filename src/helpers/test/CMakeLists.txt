add_cpputest( boyer_moore_search_test
    SOURCES
        ../boyer_moore_search.cc
)

if ( HAVE_HYPERSCAN )
    add_cpputest( hyper_search_test
        SOURCES
            ../hyper_search.cc
            ../../helpers/scratch_allocator.cc
            ../../helpers/hyper_scratch_allocator.cc
        LIBS
            ${HS_LIBRARIES}
    )
endif()

add_catch_test( bitop_test )

add_catch_test( json_stream_test
    SOURCES
        json_stream_test.cc
        ../json_stream.cc
)

