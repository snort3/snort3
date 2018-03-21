
set( FILE_API_INCLUDES
    file_api.h
    file_config.h
    file_flows.h
    file_identifier.h 
    file_lib.h
    file_module.h 
    file_policy.h
    file_segment.h
    file_service.h 
)

add_library ( file_api OBJECT
    ${FILE_API_INCLUDES}
    circular_buffer.cc 
    circular_buffer.h
    file_capture.cc
    file_capture.h
    file_cache.cc
    file_cache.h
    file_config.cc 
    file_flows.cc 
    file_identifier.cc
    file_lib.cc 
    file_log.cc 
    file_mempool.cc
    file_mempool.h
    file_module.cc
    file_policy.cc
    file_segment.cc
    file_service.cc 
    file_stats.cc 
    file_stats.h
)

install (FILES ${FILE_API_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/file_api"
)
