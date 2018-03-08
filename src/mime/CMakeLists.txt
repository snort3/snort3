
set( MIME_INCLUDES
    decode_b64.h
    decode_base.h
    file_mime_config.h
    file_mime_decode.h 
    file_mime_log.h 
    file_mime_paf.h 
    file_mime_process.h 
)

add_library ( mime OBJECT
    ${MIME_INCLUDES}
    file_mime_config.cc 
    file_mime_decode.cc 
    file_mime_log.cc 
    file_mime_paf.cc 
    file_mime_process.cc 
    decode_base.cc 
    decode_b64.cc
    decode_bit.cc
    decode_bit.h
    decode_buffer.cc
    decode_buffer.h
    decode_qp.cc
    decode_qp.h
    decode_uu.cc
    decode_uu.h
)

install (FILES ${MIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/mime"
)
