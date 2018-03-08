
add_subdirectory(back_orifice)
add_subdirectory(dce_rpc)
add_subdirectory(dnp3)
add_subdirectory(dns)
add_subdirectory(ftp_telnet)
add_subdirectory(gtp)
add_subdirectory(imap)
add_subdirectory(modbus)
add_subdirectory(http_inspect)
add_subdirectory(http2_inspect)
add_subdirectory(pop)
add_subdirectory(rpc_decode)
add_subdirectory(sip)
add_subdirectory(smtp)
add_subdirectory(ssh)
add_subdirectory(ssl)
add_subdirectory(wizard)

if (STATIC_INSPECTORS)
    set (STATIC_INSPECTOR_OBJS
        $<TARGET_OBJECTS:back_orifice>
        $<TARGET_OBJECTS:dce_rpc>
        $<TARGET_OBJECTS:dnp3>
        $<TARGET_OBJECTS:dns>
        $<TARGET_OBJECTS:ftp_telnet>
        $<TARGET_OBJECTS:gtp_inspect>
        $<TARGET_OBJECTS:modbus>
        $<TARGET_OBJECTS:rpc_decode>
        $<TARGET_OBJECTS:ssh>
        $<TARGET_OBJECTS:wizard>
    )
endif()

set(STATIC_SERVICE_INSPECTOR_PLUGINS
    $<TARGET_OBJECTS:http_inspect>
    $<TARGET_OBJECTS:http2_inspect>
    $<TARGET_OBJECTS:imap>
    $<TARGET_OBJECTS:pop>
    $<TARGET_OBJECTS:sip>
    $<TARGET_OBJECTS:smtp>
    $<TARGET_OBJECTS:ssl>
    ${STATIC_INSPECTOR_OBJS}
    CACHE INTERNAL "STATIC_SERVICE_INSPECTOR_PLUGINS"
)

add_library( service_inspectors OBJECT
    service_inspectors.cc
    service_inspectors.h
)

