
set( FILE_LIST
    tcp_pdu.cc
    tcp_pdu.h
    tcp_pdu_splitter.cc
)

if (STATIC_INSPECTORS)
    add_library( tcp_pdu OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(tcp_pdu inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

add_subdirectory(test)

