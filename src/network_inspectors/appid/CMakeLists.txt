set( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-strict-aliasing" )

set ( APPID_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR} )

set ( CP_APPID_SOURCES
	client_plugins/client_app_aim.cc
	client_plugins/client_app_aim.h
	client_plugins/client_app_api.h
	client_plugins/client_app_base.cc
	client_plugins/client_app_base.h
	client_plugins/client_app_bit.cc
	client_plugins/client_app_bit_tracker.cc
	client_plugins/client_app_config.h
	client_plugins/client_app_msn.cc
	client_plugins/client_app_msn.h
	client_plugins/client_app_rtp.cc
	client_plugins/client_app_smtp.cc
	client_plugins/client_app_smtp.h
	client_plugins/client_app_ssh.cc
	client_plugins/client_app_timbuktu.cc
	client_plugins/client_app_tns.cc
	client_plugins/client_app_vnc.cc
	client_plugins/client_app_ym.cc
	client_plugins/client_app_ym.h
)

set ( SP_APPID_SOURCES
	service_plugins/dcerpc.cc
	service_plugins/dcerpc.h
	service_plugins/service_api.h
	service_plugins/service_base.cc
	service_plugins/service_base.h
	service_plugins/service_battle_field.cc
	service_plugins/service_battle_field.h
	service_plugins/service_bgp.cc
	service_plugins/service_bgp.h
	service_plugins/service_bit.cc
	service_plugins/service_bootp.cc
	service_plugins/service_bootp.h
	service_plugins/service_config.h
	service_plugins/service_dcerpc.cc
	service_plugins/service_dcerpc.h
	service_plugins/service_direct_connect.cc
	service_plugins/service_direct_connect.h
	service_plugins/service_flap.cc
	service_plugins/service_flap.h
	service_plugins/service_ftp.cc
	service_plugins/service_ftp.h
	service_plugins/service_irc.cc
	service_plugins/service_irc.h
	service_plugins/service_lpr.cc
	service_plugins/service_lpr.h
	service_plugins/service_mdns.cc
	service_plugins/service_mdns.h
	service_plugins/service_mysql.cc
	service_plugins/service_mysql.h
	service_plugins/service_netbios.cc
	service_plugins/service_netbios.h
	service_plugins/service_nntp.cc
	service_plugins/service_nntp.h
	service_plugins/service_ntp.cc
	service_plugins/service_ntp.h
	service_plugins/service_radius.cc
	service_plugins/service_radius.h
	service_plugins/service_rexec.cc
	service_plugins/service_rexec.h
	service_plugins/service_rfb.cc
	service_plugins/service_rfb.h
	service_plugins/service_rlogin.cc
	service_plugins/service_rlogin.h
	service_plugins/service_rpc.cc
	service_plugins/service_rpc.h
	service_plugins/service_rshell.cc
	service_plugins/service_rshell.h
	service_plugins/service_rsync.cc
	service_plugins/service_rsync.h
	service_plugins/service_rtmp.cc
	service_plugins/service_rtmp.h
	service_plugins/service_smtp.cc
	service_plugins/service_smtp.h
	service_plugins/service_snmp.cc
	service_plugins/service_snmp.h
	service_plugins/service_ssh.cc
	service_plugins/service_ssh.h
	service_plugins/service_ssl.cc
	service_plugins/service_ssl.h
	service_plugins/service_telnet.cc
	service_plugins/service_telnet.h
	service_plugins/service_tftp.cc
	service_plugins/service_tftp.h
	service_plugins/service_timbuktu.cc
	service_plugins/service_tns.cc
	service_plugins/service_util.h
)

set ( DP_APPID_SOURCES
	detector_plugins/detector_api.h
	detector_plugins/detector_base.cc
	detector_plugins/detector_base.h
	detector_plugins/detector_dns.cc
	detector_plugins/detector_dns.h
	detector_plugins/detector_http.cc
	detector_plugins/detector_http.h
	detector_plugins/detector_imap.cc
	detector_plugins/detector_kerberos.cc
	detector_plugins/detector_pattern.cc
	detector_plugins/detector_pattern.h
	detector_plugins/detector_pop3.cc
	detector_plugins/detector_sip.cc
	detector_plugins/detector_sip.h
	detector_plugins/http_url_patterns.cc
	detector_plugins/http_url_patterns.h
)

set ( UTIL_APPID_SOURCES
	util/common_util.h
	util/fw_avltree.cc
	util/fw_avltree.h
	util/ip_funcs.cc
	util/ip_funcs.h
	util/network_set.cc
	util/network_set.h
	util/output_file.cc
	util/output_file.h
	util/sfksearch.cc
	util/sfksearch.h
	util/sf_mlmp.cc
	util/sf_mlmp.h
	util/sf_multi_mpse.cc
	util/sf_multi_mpse.h
	util/sfutil.cc
	util/sfutil.h
)

set ( APPID_SOURCES
    app_forecast.cc
    app_forecast.h
    appid_api.cc
    appid_api.h
    appid_config.cc
    appid_config.h
    appid_flow_data.cc
    appid_flow_data.h
    appid.h
    appid_inspector.cc
    appid_inspector.h
    appid_module.cc
    appid_module.h
    appid_stats.cc
    appid_stats.h
    app_info_table.cc
    app_info_table.h
    application_ids.h
    dns_defs.h
    flow_error.h
    fw_appid.cc
    fw_appid.h
    host_port_app_cache.cc
    host_port_app_cache.h
    http_common.h
    length_app_cache.cc
    length_app_cache.h
    lua_detector_api.cc
    lua_detector_api.h
    lua_detector_flow_api.cc
    lua_detector_flow_api.h
    lua_detector_module.cc
    lua_detector_module.h
    lua_detector_util.h
    service_state.cc
    service_state.h
    thirdparty_appid_api.h
    thirdparty_appid_types.h
    thirdparty_appid_utils.cc
    thirdparty_appid_utils.h
    )


if (STATIC_INSPECTORS)
    add_library(appid STATIC
    	${APPID_SOURCES}
    	${CP_APPID_SOURCES}
    	${DP_APPID_SOURCES}
    	${SP_APPID_SOURCES}
    	${UTIL_APPID_SOURCES}
    )
else (STATIC_INSPECTORS)
    add_shared_library(appid inspectors
    	${APPID_SOURCES}
    	${CP_APPID_SOURCES}
    	${DP_APPID_SOURCES}
    	${SP_APPID_SOURCES}
    	${UTIL_APPID_SOURCES}
    )
endif (STATIC_INSPECTORS)

target_include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

#  FIXIT-H: Add unit tests

#install (FILES ${APPID_INCLUDES}
#    DESTINATION "${INCLUDE_INSTALL_PATH}/appid"
#)
