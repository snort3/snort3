
add_example_library(ips_urg ips_options ips_urg.cc)

install (
    FILE find.lua
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/ips_options"
)
