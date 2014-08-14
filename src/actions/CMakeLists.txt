
set ( ACTIONS_INCLUDES
    actions.h
)

set (IPS_ACTION_SOURCES
    actions.cc
    ips_actions.cc
    ips_actions.h
)

set( PLUGIN_LIST
    act_react.cc
    act_reject.cc
    act_resp.cc
    )

if (STATIC_IPS_ACTIONS)

    add_library ( ips_actions STATIC
        ${IPS_ACTION_SOURCES}
        ${PLUGIN_LIST}
    )

else (STATIC_IPS_ACTIONS)

    add_library ( ips_actions STATIC
        ${IPS_ACTION_SOURCES}
    )

    add_shared_library(act_react actions act_react.cc)
    add_shared_library(act_reject actions act_reject.cc)
    add_shared_library(act_resp actions act_resp.cc)

endif (STATIC_IPS_ACTIONS)

install (FILES ${ACTIONS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/actions"
)

