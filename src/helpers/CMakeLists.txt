add_library (helpers STATIC
    base64_encoder.cc
    base64_encoder.h
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

target_link_libraries(helpers
    log
    utils
)
