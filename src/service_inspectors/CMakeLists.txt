
add_subdirectory(back_orifice)
add_subdirectory(ftp_telnet)
add_subdirectory(dns)
add_subdirectory(http_inspect)
add_subdirectory(imap)
add_subdirectory(nhttp_inspect)
add_subdirectory(pop)
add_subdirectory(rpc_decode)
add_subdirectory(sip)
add_subdirectory(smtp)
add_subdirectory(ssh)
add_subdirectory(ssl)
add_subdirectory(wizard)

if (STATIC_INSPECTORS)
    set (STATIC_INSECTOR_LIBS
        back_orifice
        ftp_telnet
        dns
        imap
        nhttp_inspect
        pop
        rpc_decode
        smtp
        ssh
        wizard
    )
endif()

add_library( service_inspectors STATIC
    service_inspectors.cc
    service_inspectors.h
)

target_link_libraries( service_inspectors
    http_inspect
    ${STATIC_INSECTOR_LIBS}
)
