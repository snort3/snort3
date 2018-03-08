
set( FILE_LIST
    dns.cc
    dns.h
    dns_module.cc
    dns_module.h
)

if (STATIC_INSPECTORS)
    add_library( dns OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(dns inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
