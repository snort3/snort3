set( FILE_LIST
    s7comm.cc
    s7comm.h
    s7comm_decode.cc
    s7comm_decode.h
    s7comm_module.cc
    s7comm_module.h
    s7comm_paf.cc
    s7comm_paf.h
    ips_s7comm_content.cc
    ips_s7comm_func.cc
    ips_s7comm_opcode.cc
)

if (STATIC_INSPECTORS)
    add_library(s7commplus OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(s7commplus inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

