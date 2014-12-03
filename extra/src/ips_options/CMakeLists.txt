
add_example_library(ips_urg ips_options ips_urg.cc)

install (
    FILES find.lua
    DESTINATION "${EX_INSTALL_PATH}/ips_options"
)
