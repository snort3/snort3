


###################################
#######  adding pim library #######
###################################

add_library(pim SHARED
    pim.cc
)

set_target_properties ( pim
    PROPERTIES
    LINK_FLAGS "-export-dynamic -shared"
)

install (TARGETS pim
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/codecs"
)


###################################
#### adding Token ring library ####
###################################

add_library(token_ring SHARED
    token_ring.cc
    token_ring_module.h
    token_ring_module.cc
)

set_target_properties ( token_ring
    PROPERTIES
    LINK_FLAGS "-export-dynamic -shared"
)

install (TARGETS token_ring
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/codecs"
)
