
set( FILE_LIST
    ssl_inspector.cc
    ssl_inspector.h
    ssl_config.h
    ssl_module.cc
    ssl_module.h
    ips_ssl_state.cc
    ips_ssl_version.cc
)

# can't be be linked dynamically yet
#if (STATIC_INSPECTORS)
    add_library( ssl STATIC ${FILE_LIST})

#else (STATIC_INSPECTORS)
    #add_shared_library(ssl inspectors ${FILE_LIST})

#endif (STATIC_INSPECTORS)

