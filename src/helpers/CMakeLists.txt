
set (HELPERS_INCLUDES
    base64_encoder.h
)

add_library (helpers OBJECT
    ${HELPERS_INCLUDES}
    base64_encoder.cc
    chunk.cc
    chunk.h
    directory.cc
    directory.h
    discovery_filter.cc
    discovery_filter.h
    flag_context.h
    markup.cc
    markup.h
    process.cc
    process.h
    ring.h
    ring_logic.h
)

install (FILES ${HELPERS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/helpers"
)

add_catch_test( base64_encoder_test
    NO_TEST_SOURCE
    SOURCES
        base64_encoder.cc
)
