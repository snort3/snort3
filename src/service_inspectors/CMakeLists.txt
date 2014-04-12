
add_subdirectory(back_orifice)
add_subdirectory(ftp_telnet)
add_subdirectory(http_inspect)
add_subdirectory(rpc_decode)

add_library( service_inspectors STATIC
    service_inspectors.cc
    service_inspectors.h
)

target_link_libraries( service_inspectors
    back_orifice
    ftp_telnet
    http_inspect
    rpc_decode
)
