
set ( ACTIONS_INCLUDES
    actions.h
)

set (ACTION_SOURCES
    actions.cc
    ips_actions.cc
    ips_actions.h
)

set( PLUGIN_LIST
    act_reject.cc
    )

if (STATIC_IPS_ACTIONS)

    add_library ( ips_actions STATIC
        ${ACTION_SOURCES}
        ${PLUGIN_LIST}
    )

    target_link_libraries(ips_actions
        packet_io
    )

else (STATIC_IPS_ACTIONS)

    add_library ( ips_actions STATIC
        ${ACTION_SOURCES}
    )

    add_shared_library(act_reject ips_actions act_reject.cc)

endif (STATIC_IPS_ACTIONS)

install (FILES ${ACTIONS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/actions"
)

