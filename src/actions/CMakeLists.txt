
set (IPS_ACTION_SOURCES
    actions_module.cc
    actions_module.h
    ips_actions.cc
    ips_actions.h
)

set( PLUGIN_LIST
    act_alert.cc
    act_block.cc
    act_drop.cc
    act_file_id.cc
    act_log.cc
    act_pass.cc
    act_react.cc
    act_reject.cc
    act_replace.cc
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

    add_dynamic_module(act_alert ips_actions act_alert.cc actions_module.cc)
    add_dynamic_module(act_block ips_actions act_block.cc actions_module.cc)
    add_dynamic_module(act_drop ips_actions act_drop.cc actions_module.cc)
    add_dynamic_module(act_file_id ips_actions act_file_id.cc actions_module.cc)
    add_dynamic_module(act_log ips_actions act_log.cc actions_module.cc)
    add_dynamic_module(act_pass ips_actions act_pass.cc actions_module.cc)
    add_dynamic_module(act_react ips_actions act_react.cc actions_module.cc)
    add_dynamic_module(act_reject ips_actions act_reject.cc actions_module.cc)
    add_dynamic_module(act_replace ips_actions act_replace.cc actions_module.cc)

endif (STATIC_IPS_ACTIONS)

