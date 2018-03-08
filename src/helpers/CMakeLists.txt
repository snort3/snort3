
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

