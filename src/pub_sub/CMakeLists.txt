set (PUB_SUB_INCLUDES
    appid_debug_log_event.h
    appid_events.h
    cip_events.h
    data_decrypt_event.h
    daq_message_event.h
    dcerpc_events.h
    dhcp_events.h
    efp_process_event.h
    expect_events.h
    finalize_packet_event.h
    http_events.h
    http_request_body_event.h
    opportunistic_tls_event.h
    sip_events.h
    smb_events.h
    ssh_events.h
)

add_library( pub_sub OBJECT
    ${PUB_SUB_INCLUDES}
    cip_events.cc
    http_events.cc
    http_request_body_event.cc
    sip_events.cc
)

install (FILES ${PUB_SUB_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/pub_sub"
)

add_subdirectory ( test )

