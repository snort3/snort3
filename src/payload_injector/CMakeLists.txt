set (PAYLOAD_INJECTOR_INCLUDES
    payload_injector_module.h
)

add_library ( payload_injector OBJECT
    ${PAYLOAD_INJECTOR_INCLUDES}
    payload_injector_module.cc
)

install(FILES ${PAYLOAD_INJECTOR_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/payload_injector/"
)

add_subdirectory(test)
