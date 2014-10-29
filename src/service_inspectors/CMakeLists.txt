
add_subdirectory(back_orifice)
add_subdirectory(ftp_telnet)
add_subdirectory(http_inspect)
add_subdirectory(nhttp_inspect)
add_subdirectory(rpc_decode)
add_subdirectory(wizard)

if (STATIC_INSPECTORS)
    set (STATIC_INSECTOR_LIBS
        wizard
        rpc_decode
        back_orifice
        ftp_telnet
        nhttp_inspect
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
