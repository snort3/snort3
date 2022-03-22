set (REPUTATION_INCLUDES
    reputation_common.h
)

add_library( reputation OBJECT
    reputation_commands.cc
    reputation_commands.h
    reputation_config.h
    reputation_inspect.h
    reputation_inspect.cc
    reputation_module.cc
    reputation_module.h
    reputation_parse.cc
    reputation_parse.h
)

install(FILES ${REPUTATION_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/network_inspectors/reputation"
)

