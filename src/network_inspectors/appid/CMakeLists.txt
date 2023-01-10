set (APPID_INCLUDES
    appid_api.h
    appid_app_descriptor.h
    appid_debug.h
    appid_dns_session.h
    appid_http_session.h
    appid_session_api.h
    appid_types.h
    application_ids.h
    tp_appid_module_api.h
    tp_appid_session_api.h
    tp_appid_types.h
)

set ( APPID_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR} )

set ( CP_APPID_SOURCES
    client_plugins/client_app_bit.cc
    client_plugins/client_app_bit.h
    client_plugins/client_app_bit_tracker.cc
    client_plugins/client_app_bit_tracker.h
    client_plugins/client_detector.cc
    client_plugins/client_detector.h
    client_plugins/client_app_msn.cc
    client_plugins/client_app_msn.h
    client_plugins/client_app_rtp.cc
    client_plugins/client_app_rtp.h
    client_plugins/client_app_timbuktu.cc
    client_plugins/client_app_timbuktu.h
    client_plugins/client_app_tns.cc
    client_plugins/client_app_tns.h
    client_plugins/client_app_vnc.cc
    client_plugins/client_app_vnc.h
    client_plugins/client_detector.cc
    client_plugins/client_detector.h
    client_plugins/client_discovery.cc
    client_plugins/client_discovery.h
    client_plugins/eve_ca_patterns.cc
    client_plugins/eve_ca_patterns.h
)

set ( SP_APPID_SOURCES
    service_plugins/alpn_patterns.cc
    service_plugins/alpn_patterns.h
    service_plugins/dcerpc.cc
    service_plugins/dcerpc.h
    service_plugins/service_bgp.cc
    service_plugins/service_bgp.h
    service_plugins/service_bit.cc
    service_plugins/service_bit.h
    service_plugins/service_bootp.cc
    service_plugins/service_bootp.h
    service_plugins/service_dcerpc.cc
    service_plugins/service_dcerpc.h
    service_plugins/service_detector.cc
    service_plugins/service_detector.h
    service_plugins/service_discovery.cc
    service_plugins/service_discovery.h
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
    service_plugins/service_regtest.cc
    service_plugins/service_regtest.h
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
    service_plugins/service_snmp.cc
    service_plugins/service_snmp.h
    service_plugins/service_ssl.cc
    service_plugins/service_ssl.h
    service_plugins/service_telnet.cc
    service_plugins/service_telnet.h
    service_plugins/service_tftp.cc
    service_plugins/service_tftp.h
    service_plugins/service_timbuktu.cc
    service_plugins/service_timbuktu.h
    service_plugins/service_tns.cc
    service_plugins/service_tns.h
)

set ( DP_APPID_SOURCES
    detector_plugins/cip_patterns.cc
    detector_plugins/cip_patterns.h
    detector_plugins/detector_dns.cc
    detector_plugins/detector_dns.h
    detector_plugins/detector_imap.cc
    detector_plugins/detector_imap.h
    detector_plugins/detector_kerberos.cc
    detector_plugins/detector_kerberos.h
    detector_plugins/detector_pattern.cc
    detector_plugins/detector_pattern.h
    detector_plugins/detector_pop3.cc
    detector_plugins/detector_pop3.h
    detector_plugins/detector_sip.cc
    detector_plugins/detector_sip.h
    detector_plugins/detector_smtp.cc
    detector_plugins/detector_smtp.h
    detector_plugins/dns_patterns.cc
    detector_plugins/dns_patterns.h
    detector_plugins/http_url_patterns.cc
    detector_plugins/http_url_patterns.h
    detector_plugins/sip_patterns.cc
    detector_plugins/sip_patterns.h
    detector_plugins/ssh_patterns.cc
    detector_plugins/ssh_patterns.h
    detector_plugins/ssl_patterns.cc
    detector_plugins/ssl_patterns.h
)

set ( UTIL_APPID_SOURCES
    appid_utils/ip_funcs.h
    appid_utils/sf_mlmp.cc
    appid_utils/sf_mlmp.h
)

set ( APPID_SOURCES
    appid_api.cc
    appid_api.h
    appid_app_descriptor.cc
    appid_app_descriptor.h
    appid_config.cc
    appid_config.h
    appid_cip_event_handler.cc
    appid_cip_event_handler.h
    appid_data_decrypt_event_handler.h
    appid_debug.cc
    appid_debug.h
    appid_detector.cc
    appid_detector.h
    appid_discovery.cc
    appid_discovery.h
    appid_dns_session.h
    appid_eve_process_event_handler.cc
    appid_eve_process_event_handler.h
    appid_ha.cc
    appid_ha.h
    appid_http_session.cc
    appid_http_session.h
    appid_httpx_req_body_event_handler.h
    appid_opportunistic_tls_event_handler.h
    appid_peg_counts.h
    appid_peg_counts.cc
    appid_service_event_handler.cc
    appid_service_event_handler.h
    appid_session.cc
    appid_session.h
    appid_session_api.cc
    appid_session_api.h
    appid_types.h
    appid_inspector.cc
    appid_inspector.h
    appid_module.cc
    appid_module.h
    appid_ssh_event_handler.cc
    appid_ssh_event_handler.h
    appid_stats.cc
    appid_stats.h
    app_info_table.cc
    app_info_table.h
    application_ids.h
    host_port_app_cache.cc
    host_port_app_cache.h
    appid_http_event_handler.cc
    appid_http_event_handler.h
    ips_appid_option.cc
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
    tp_appid_utils.cc
    tp_lib_handler.cc
    tp_lib_handler.h
    tp_appid_types.h
)

#if (STATIC_INSPECTORS)
add_library(appid OBJECT
    ${APPID_SOURCES}
    ${CP_APPID_SOURCES}
    ${DP_APPID_SOURCES}
    ${SP_APPID_SOURCES}
    ${UTIL_APPID_SOURCES}
)
#else (STATIC_INSPECTORS)
#    add_dynamic_module(appid inspectors
#        ${APPID_SOURCES}
#        ${CP_APPID_SOURCES}
#        ${DP_APPID_SOURCES}
#        ${SP_APPID_SOURCES}
#        ${UTIL_APPID_SOURCES}
#    )
#endif (STATIC_INSPECTORS)

target_include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

add_subdirectory(service_plugins/test)
add_subdirectory(detector_plugins/test)
add_subdirectory(client_plugins/test)
add_subdirectory(test)

install (FILES ${APPID_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/network_inspectors/appid"
)
