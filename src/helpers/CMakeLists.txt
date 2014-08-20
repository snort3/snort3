

add_library (helpers STATIC
    chunk.cc
    chunk.h
    directory.cc
    directory.h
    markup.cc
    markup.h
    process.cc
    process.h
    swapper.h
)


target_link_libraries(helpers
    log
    utils
)
