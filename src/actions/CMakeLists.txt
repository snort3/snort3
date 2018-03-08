
set ( ACTIONS_INCLUDES
    actions.h
)

set (IPS_ACTION_SOURCES
    actions.cc
    ips_actions.cc
    ips_actions.h
    act_replace.cc
    act_replace.h
)

set( PLUGIN_LIST
    act_react.cc
    act_reject.cc
    )

if (STATIC_IPS_ACTIONS)
    add_library ( ips_actions OBJECT
        ${IPS_ACTION_SOURCES}
        ${PLUGIN_LIST}
    )

else (STATIC_IPS_ACTIONS)

    add_library ( ips_actions OBJECT
        ${IPS_ACTION_SOURCES}
    )

    add_dynamic_module(act_react ips_actions act_react.cc)
    add_dynamic_module(act_reject ips_actions act_reject.cc)

endif (STATIC_IPS_ACTIONS)

install (FILES ${ACTIONS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/actions"
)

