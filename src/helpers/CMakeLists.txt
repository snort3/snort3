
if ( HAVE_HYPERSCAN )
    set(HYPER_HEADERS
        hyper_scratch_allocator.h
        hyper_search.h
    )
    set(HYPER_SOURCES
        hyper_scratch_allocator.cc
        hyper_search.cc
    )
endif ()

set (HELPERS_INCLUDES
    ${HYPER_HEADERS}
    base64_encoder.h
    ber.h
    bitop.h
    boyer_moore.h
    boyer_moore_search.h
    buffer_data.h
    event_gen.h
    infractions.h
    json_stream.h
    literal_search.h
    memcap_allocator.h
    ring2.h
    scratch_allocator.h
    sigsafe.h
    utf.h
)

add_library (helpers OBJECT
    ${HELPERS_INCLUDES}
    ${HYPER_SOURCES}
    base64_encoder.cc
    ber.cc
    boyer_moore.cc
    boyer_moore_search.cc
    buffer_data.cc
    directory.cc
    directory.h
    discovery_filter.cc
    discovery_filter.h
    flag_context.h
    grouped_list.h
    json_stream.cc
    literal_search.cc
    markup.cc
    markup.h
    primed_allocator.h
    ring.h
    ring_logic.h
    sigsafe.cc
    scratch_allocator.cc
    streambuf.cc
    streambuf.h
    utf.cc
)

install (FILES ${HELPERS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/helpers"
)

add_catch_test( base64_encoder_test
    NO_TEST_SOURCE
    SOURCES
        base64_encoder.cc
)

add_catch_test( sigsafe_test
    NO_TEST_SOURCE
    SOURCES
        sigsafe.cc
)

add_subdirectory(test)

