

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
    decode_base.cc 
    decode_base.h
    decode_b64.cc
    decode_b64.h
    decode_bit.cc
    decode_bit.h
    decode_buffer.cc
    decode_buffer.h
    decode_qp.cc
    decode_qp.h
    decode_uu.cc
    decode_uu.h
    
)

target_link_libraries(mime file_api)

