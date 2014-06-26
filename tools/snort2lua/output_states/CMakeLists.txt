

add_library(output_states
    output_api.h
    output_api.cc
)

target_link_libraries( output_states
    util
    conversion_data
)
