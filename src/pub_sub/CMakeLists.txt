set (PUB_SUB_INCLUDES
    appid_events.h
    cip_events.h
    daq_message_event.h
    expect_events.h
    finalize_packet_event.h
    http_events.h
    sip_events.h
)

add_library( pub_sub OBJECT
    ${PUB_SUB_INCLUDES}
    cip_events.cc
    http_events.cc
    sip_events.cc
)

install (FILES ${PUB_SUB_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/pub_sub"
)

