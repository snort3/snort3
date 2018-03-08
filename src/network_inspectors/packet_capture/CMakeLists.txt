set ( FILE_LIST
    capture_module.cc
    capture_module.h
    packet_capture.cc
    packet_capture.h
)

if (STATIC_INSPECTORS)
    add_library(packet_capture OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(packet_capture inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
