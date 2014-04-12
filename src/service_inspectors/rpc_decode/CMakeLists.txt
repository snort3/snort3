
set( FILE_LIST
    rpc_decode.cc
    rpc_module.h
    rpc_module.cc
)

if (STATIC_INSPECTORS)
    add_library( rpc_decode STATIC ${FILE_LIST})

else ()
    add_shared_library(rpc_decode inspectors ${FILE_LIST})

endif ()

