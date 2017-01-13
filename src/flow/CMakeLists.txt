set (FLOW_INCLUDES
    flow.h
    flow_key.h
)

add_library (flow STATIC
    ${FLOW_INCLUDES}
    expect_cache.cc
    expect_cache.h
    flow.cc
    flow_cache.cc
    flow_cache.h
    flow_config.h
    flow_control.cc
    flow_control.h
    flow_key.cc
    ha.cc
    ha.h
    ha_module.cc
    ha_module.h
    prune_stats.h
    session.h
)

target_link_libraries(flow
    protocols
)

install(FILES ${FLOW_INCLUDES}
    DESTINATION ${INCLUDE_INSTALL_PATH}/flow
)
