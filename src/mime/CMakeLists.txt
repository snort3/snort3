
set( MIME_INCLUDES
    decode_b64.h
    decode_base.h
    decode_bit.h
    decode_buffer.h
    decode_qp.h
    decode_uu.h
    file_mime_config.h
    file_mime_decode.h 
    file_mime_log.h 
    file_mime_paf.h 
    file_mime_process.h 
)

add_library ( mime STATIC
    ${MIME_INCLUDES}
    file_mime_config.cc 
    file_mime_decode.cc 
    file_mime_log.cc 
    file_mime_paf.cc 
    file_mime_process.cc 
    decode_base.cc 
    decode_b64.cc
    decode_bit.cc
    decode_buffer.cc
    decode_qp.cc
    decode_uu.cc
    
)

target_link_libraries(mime file_api)

install (FILES ${MIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/mime"
)
