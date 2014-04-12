
add_subdirectory(plugins)

add_library ( sidechannel STATIC
    dmq.cc
    dmq.h
    rbmq.cc
    rbmq.h
    sidechannel.cc
    sidechannel.h
    sidechannel_define.h
)

