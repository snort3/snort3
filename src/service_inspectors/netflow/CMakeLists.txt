
set ( FILE_LIST
    netflow_headers.h
    netflow_module.cc
    netflow_module.h
    netflow.cc
)

if (STATIC_INSPECTORS)
    add_library( netflow OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(netflow inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)