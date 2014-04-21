
set ( ACTIONS_INCLUDES
    actions.h
)

add_library(actions STATIC
    ${ACTIONS_INCLUDES}
    actions.cc
)

install (FILES ${ACTIONS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/actions"
)
