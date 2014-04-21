
set (PROTOCOL_HEADERS
    packet.h
    sf_protocols.h
)

add_library (protocols STATIC
    checksum.h
    decode.cc 
    decode.h 
    encode.cc 
    encode.h 
    decode_module.cc
    decode_module.h
    sf_protocols.h
    ${PROTOCOL_HEADERS}
)

install (FILES ${PROTOCOL_HEADERS}
    DESTINATION "${INCLUDE_INSTALL_PATH}/protocols"
)


