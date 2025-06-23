
add_catch_test( bitop_test )

add_cpputest( boyer_moore_test
    SOURCES
        ../boyer_moore.cc
)

add_cpputest( boyer_moore_search_test
    SOURCES
        ../boyer_moore_search.cc
)

add_catch_test( grouped_list_test
    SOURCES
        ../grouped_list.h
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

add_catch_test( json_stream_test
    SOURCES
        json_stream_test.cc
        ../json_stream.cc
)

add_cpputest( memcap_allocator_test )

add_catch_test( streambuf_test
    SOURCES
        ../streambuf.cc
)

add_catch_test( ring2_test
    SOURCES
        ../ring2.h
)

if (ENABLE_BENCHMARK_TESTS)

    add_catch_test( ring2_benchmark
        SOURCES
            ../ring2.h
    )

endif(ENABLE_BENCHMARK_TESTS)
