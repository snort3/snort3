
set( FILE_LIST
    ssh.cc
    ssh.h
    ssh_config.h
    ssh_module.cc
    ssh_module.h
)

if (STATIC_INSPECTORS)
    add_library( ssh OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(ssh inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
