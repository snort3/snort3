set ( LATENCY_INCLUDES
    packet_latency.h
    latency_rules.h
    )

set ( LATENCY_SOURCES
    latency_timer.h
    latency_util.h
    packet_latency.cc
    latency_module.cc
    )

add_library ( latency STATIC ${LATENCY_SOURCES} )

install ( FILES ${LATENCY_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/latency"
)
