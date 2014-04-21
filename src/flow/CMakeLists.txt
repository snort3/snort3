
set (FLOW_INCLUDES
    flow.h
    flow_key.h
)

add_library ( flow STATIC
    ${FLOW_INCLUDES}
    flow.cc 
    flow_key.cc 
    flow_cache.cc 
    flow_cache.h 
    expect_cache.cc 
    expect_cache.h 
    flow_control.cc 
    flow_control.h 
    session.h
)

set_target_properties(flow
    PROPERTIES
    COMPILE_FLAGS "-fvisibility=default"
)

install(FILES ${FLOW_INCLUDES}
    DESTINATION ${INCLUDE_INSTALL_PATH}/flow
)
