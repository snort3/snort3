set( FILE_LIST
    cip.cc
    cip.h
    cip_definitions.h
    cip_module.cc
    cip_module.h
    cip_paf.cc
    cip_paf.h
    cip_parsing.cc
    cip_parsing.h
    cip_session.cc
    cip_session.h
    ips_cip_attribute.cc
    ips_cip_class.cc
    ips_cip_connpathclass.cc
    ips_cip_enipcommand.cc
    ips_cip_enipreq.cc
    ips_cip_eniprsp.cc
    ips_cip_instance.cc
    ips_cip_req.cc
    ips_cip_rsp.cc
    ips_cip_service.cc
    ips_cip_status.cc
)

if (STATIC_INSPECTORS)
    add_library(cip OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(cip inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

