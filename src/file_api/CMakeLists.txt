
add_subdirectory("libs")

add_library ( file_api STATIC
    file_api.h 
    file_service.cc 
    file_service.h 
    file_service_config.cc 
    file_service_config.h 
    file_mime_process.h 
    file_mime_process.cc 
    file_resume_block.cc 
    file_resume_block.h 
    file_mime_config.cc 
    file_mime_config.h
)
