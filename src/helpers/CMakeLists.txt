

add_library (helpers STATIC
    directory.cc
    directory.h
    process.cc
    process.h
    swapper.h
)


target_link_libraries(helpers
    log
    utils
)
