
set( FILE_LIST
    tlv_pdu.cc
    tlv_pdu.h
    tlv_pdu_splitter.cc
)

if (STATIC_INSPECTORS)
    add_library(tlv_pdu OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(tlv_pdu inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

add_subdirectory(test)

