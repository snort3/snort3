
add_subdirectory(back_orifice)
add_subdirectory(dce_rpc)
add_subdirectory(dnp3)
add_subdirectory(dns)
add_subdirectory(ftp_telnet)
add_subdirectory(gtp)
add_subdirectory(imap)
add_subdirectory(modbus)
add_subdirectory(http_inspect)
add_subdirectory(pop)
add_subdirectory(rpc_decode)
add_subdirectory(sip)
add_subdirectory(smtp)
add_subdirectory(ssh)
add_subdirectory(ssl)
add_subdirectory(wizard)

if (STATIC_INSPECTORS)
    set (STATIC_INSPECTOR_LIBS
        back_orifice
        dce_rpc
        dnp3
        dns
        ftp_telnet
        gtp_inspect
        modbus
        rpc_decode
        ssh
        wizard
    )
endif()

add_library( service_inspectors STATIC
    service_inspectors.cc
    service_inspectors.h
)

target_link_libraries( service_inspectors
    ${STATIC_INSPECTOR_LIBS}
    imap
    pop
    smtp
    ssl
)

