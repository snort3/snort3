
set( FILE_LIST
    dnp3.cc
    dnp3.h
    dnp3_map.cc
    dnp3_map.h
    dnp3_module.cc
    dnp3_module.h
    dnp3_reassembly.cc
    dnp3_reassembly.h
    dnp3_paf.cc
    dnp3_paf.h
    ips_dnp3_data.cc
    ips_dnp3_func.cc
    ips_dnp3_ind.cc
    ips_dnp3_obj.cc

)

if (STATIC_INSPECTORS)
    add_library(dnp3 OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(dnp3 inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

