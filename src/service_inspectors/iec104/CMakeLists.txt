set( FILE_LIST
    iec104.cc
    iec104.h
    iec104_decode.cc
    iec104_decode.h
    iec104_module.cc
    iec104_module.h
    iec104_paf.cc
    iec104_paf.h
    iec104_parse_apdu.cc
    iec104_parse_apdu.h
    iec104_parse_information_object_elements.cc
    iec104_parse_information_object_elements.h
    iec104_trace.h
    ips_iec104_apci_type.cc
    ips_iec104_asdu_func.cc
)

if (STATIC_INSPECTORS)
    add_library(iec104 OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(iec104 inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

