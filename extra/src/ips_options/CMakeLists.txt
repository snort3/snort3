
add_library( ips_urg SHARED
    ips_urg.cc
)

set_target_properties ( ips_urg
    PROPERTIES
    LINK_FLAGS "-export-dynamic -shared"
)


install (TARGETS ips_urg
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/ips_options"
)

install (FILES find.lua
    DESTINATION "${EX_INSTALL_PATH}/ips_options"
)

