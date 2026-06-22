
set (SSH_INCLUDES
    ssh_types.h
)

set( FILE_LIST
    ssh.cc
    ssh.h
    ssh_config.h
    ssh_module.cc
    ssh_module.h
    ssh_splitter.cc
    ssh_splitter.h
    ${SSH_INCLUDES}
)

if (STATIC_INSPECTORS)
    add_library( ssh OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(ssh inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

if (ENABLE_UNIT_TESTS)
    add_subdirectory(test)
endif (ENABLE_UNIT_TESTS)

install(FILES ${SSH_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/service_inspectors/ssh/"
)
