set (PUB_SUB_INCLUDES
    appid_debug_log_event.h
    appid_event_ids.h
    appid_events.h
    assistant_gadget_event.h
    cip_events.h
    data_decrypt_event.h
    daq_message_event.h
    dcerpc_events.h
    detection_events.h
    dhcp_events.h
    domain_fronting.h
    eof_event.h
    eve_process_event.h
    expect_events.h
    external_event_ids.h
    file_events.h
    file_events_ids.h
    finalize_packet_event.h
    ftp_events.h
    http_event_ids.h
    http_events.h
    http_request_body_event.h
    http_body_event.h
    http_publish_length_event.h
    http_transaction_end_event.h
    intrinsic_event_ids.h
    netflow_event.h
    opportunistic_tls_event.h
    packet_events.h
    reputation_events.h
    rna_events.h
    sip_events.h
    stream_event_ids.h
    shadowtraffic_aggregator.h
    smb_events.h
    ssh_events.h
    ssl_events.h
    dns_events.h
)

add_library( pub_sub OBJECT
    ${PUB_SUB_INCLUDES}
    cip_events.cc
    http_events.cc
    detection_events.cc
    dns_events.cc
    eof_event.cc
    http_request_body_event.cc
    http_body_event.cc
    http_transaction_end_event.cc
    sip_events.cc
)

install (FILES ${PUB_SUB_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/pub_sub"
)

add_subdirectory ( test )

