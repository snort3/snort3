set ( CLIENT_PLUGINS_SOURCES
    client_app_aim.cc
    client_app_aim.h
    client_app_api.h
    client_app_base.cc
    client_app_base.h
    client_app_bit.cc
    client_app_bit_tracker.cc
    client_app_config.h
    client_app_msn.cc
    client_app_msn.h
    client_app_rtp.cc
    client_app_smtp.cc
    client_app_smtp.h
    client_app_ssh.cc
    client_app_timbuktu.cc
    client_app_tns.cc
    client_app_vnc.cc
    client_app_ym.cc
    client_app_ym.h
    )

add_library ( appid_client_plugins STATIC
    ${CLIENT_PLUGINS_SOURCES}
)

target_include_directories ( appid_client_plugins PRIVATE ${APPID_INCLUDE_DIR} )

#  FIXIT-H: Add unit tests

#install (FILES ${CLIENT_PLUGINS_INCLUDES}
#    DESTINATION "${INCLUDE_INSTALL_PATH}/appid/client_plugins"

#)
