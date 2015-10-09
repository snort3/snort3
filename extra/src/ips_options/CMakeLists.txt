
add_example_library(ips_urg ips_options ips_urg.cc)
add_example_library(ips_pkt_num ips_options ips_pkt_num.cc)

install (
    FILES find.lua
    DESTINATION "${EX_INSTALL_PATH}/ips_options"
)
