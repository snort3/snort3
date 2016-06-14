
set ( SERVICE_PLUGINS_SOURCES
    dcerpc.cc
    dcerpc.h
    service_api.h
    service_base.cc
    service_base.h
    service_battle_field.cc
    service_battle_field.h
    service_bgp.cc
    service_bgp.h
    service_bit.cc
    service_bootp.cc
    service_bootp.h
    service_config.h
    service_dcerpc.cc
    service_dcerpc.h
    service_direct_connect.cc
    service_direct_connect.h
    service_flap.cc
    service_flap.h
    service_ftp.cc
    service_ftp.h
    service_irc.cc
    service_irc.h
    service_lpr.cc
    service_lpr.h
    service_mdns.cc
    service_mdns.h
    service_mysql.cc
    service_mysql.h
    service_netbios.cc
    service_netbios.h
    service_nntp.cc
    service_nntp.h
    service_ntp.cc
    service_ntp.h
    service_radius.cc
    service_radius.h
    service_rexec.cc
    service_rexec.h
    service_rfb.cc
    service_rfb.h
    service_rlogin.cc
    service_rlogin.h
    service_rpc.cc
    service_rpc.h
    service_rshell.cc
    service_rshell.h
    service_rsync.cc
    service_rsync.h
    service_rtmp.cc
    service_rtmp.h
    service_smtp.cc
    service_smtp.h
    service_snmp.cc
    service_snmp.h
    service_ssh.cc
    service_ssh.h
    service_ssl.cc
    service_ssl.h
    service_telnet.cc
    service_telnet.h
    service_tftp.cc
    service_tftp.h
    service_timbuktu.cc
    service_tns.cc
    service_util.h
    )

add_library ( appid_service_plugins STATIC
    ${SERVICE_PLUGINS_SOURCES}
)

target_include_directories ( appid_service_plugins PRIVATE ${APPID_INCLUDE_DIR} )

#  FIXIT-H: Add unit tests

#install (FILES ${SERVICE_PLUGINS_INCLUDES}
#    DESTINATION "${INCLUDE_INSTALL_PATH}/appid/service_plugins"
#)
