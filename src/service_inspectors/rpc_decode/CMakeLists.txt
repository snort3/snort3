
set( FILE_LIST
    rpc_decode.cc
    rpc_module.h
    rpc_module.cc
)

if (STATIC_INSPECTORS)
    add_library( rpc_decode OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(rpc_decode inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
