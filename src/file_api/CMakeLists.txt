

add_subdirectory(libs)

add_library ( file_api STATIC
    circular_buffer.cc 
    circular_buffer.h
    file_api.h
    file_capture.cc
    file_capture.h
    file_mempool.cc
    file_mempool.h
    file_mime_config.cc 
    file_mime_config.h
    file_mime_paf.h 
    file_mime_paf.cc 
    file_mime_process.h 
    file_mime_process.cc 
    file_resume_block.cc 
    file_resume_block.h 
    file_service.cc 
    file_service.h 
    file_service_config.cc 
    file_service_config.h 
    file_stats.cc 
    file_stats.h
)

target_link_libraries(file_api file)

