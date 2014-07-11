

add_library( util
    converter.h
    converter.cc
    util.h
    util.cc
)

target_link_libraries( util
    conversion_data
)
