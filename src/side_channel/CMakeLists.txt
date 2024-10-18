
add_library( side_channel OBJECT
    side_channel.cc
    side_channel.h
    side_channel_module.cc
    side_channel_module.h
    side_channel_format.cc
    side_channel_format.h
)

add_subdirectory(test)
