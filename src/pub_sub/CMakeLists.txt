set (PUB_SUB_INCLUDES
    expect_events.h
    http_events.h
    sip_events.h
)

add_library( pub_sub OBJECT
    ${PUB_SUB_INCLUDES}
    http_events.cc
    sip_events.cc
)

install (FILES ${PUB_SUB_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/pub_sub"
)

