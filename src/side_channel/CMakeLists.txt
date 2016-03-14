
add_library( side_channel STATIC
    side_channel.cc
    side_channel.h
    side_channel_module.cc
    side_channel_module.h
)

target_link_libraries(side_channel)
