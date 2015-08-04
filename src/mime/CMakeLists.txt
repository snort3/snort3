

add_library ( mime STATIC
    file_mime_config.cc 
    file_mime_config.h
    file_mime_decode.h 
    file_mime_decode.cc 
    file_mime_log.h 
    file_mime_log.cc 
    file_mime_paf.h 
    file_mime_paf.cc 
    file_mime_process.h 
    file_mime_process.cc 
    sf_email_attach_decode.cc 
    sf_email_attach_decode.h
    sf_base64decode.cc 
    sf_base64decode.h
)

target_link_libraries(mime file_api)

