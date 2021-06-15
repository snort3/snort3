set ( CONTROL_INCLUDES  control.h )

if ( ENABLE_SHELL )
    set ( SHELL_SOURCES control_mgmt.cc control_mgmt.h )
endif ( ENABLE_SHELL )

add_library ( control OBJECT
    control.cc
    ${SHELL_SOURCES}
)

install (FILES ${CONTROL_INCLUDES}
    DESTINATION ${INCLUDE_INSTALL_PATH}/control
)
