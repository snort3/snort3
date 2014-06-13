
add_library(dpx SHARED
    dpx.cc
)

set_target_properties ( dpx
    PROPERTIES
    LINK_FLAGS "-export-dynamic -shared"
)

install (TARGETS dpx
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/inspectors"
)
