

add_library ( file_api STATIC
    circular_buffer.cc 
    circular_buffer.h
    file_api.h
    file_capture.cc
    file_capture.h
    file_config.cc 
    file_config.h 
    file_enforcer.cc 
    file_enforcer.h 
    file_flows.cc 
    file_flows.h
    file_identifier.h 
    file_identifier.cc
    file_lib.cc 
    file_lib.h 
    file_log.cc 
    file_mempool.cc
    file_mempool.h
    file_module.cc
    file_module.h
    file_policy.cc 
    file_policy.h
    file_service.cc 
    file_service.h 
    file_stats.cc 
    file_stats.h
)

target_link_libraries(file_api mime)

