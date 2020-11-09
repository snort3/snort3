set (PAYLOAD_INJECTOR_INCLUDES
    payload_injector.h
)

add_library ( payload_injector OBJECT
    ${PAYLOAD_INJECTOR_INCLUDES}
    payload_injector.cc
    payload_injector_config.h
    payload_injector_module.cc
    payload_injector_module.h    
    payload_injector_translate_page.cc
)

install(FILES ${PAYLOAD_INJECTOR_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/payload_injector/"
)

add_subdirectory(test)
