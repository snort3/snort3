add_cpputest( boyer_moore_test
    SOURCES
        ../boyer_moore.cc
)

add_cpputest( memcap_allocator_test )

add_catch_test( streambuf_test
    SOURCES
        ../streambuf.cc
)

add_catch_test( grouped_list_test
    SOURCES
        ../grouped_list.h
)
