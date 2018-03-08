set (
    PP_CODEC_DEPENDENCIES
    pp_codec_data_iface.cc
    pp_enc_state_iface.cc
    pp_buffer_iface.cc
    pp_event_iface.cc
    pp_daq_pkthdr_iface.cc
)

set (
    PP_CODEC_SOURCES
    pp_codec.cc
    pp_codec_iface.cc
    ${PP_CODEC_DEPENDENCIES}
)

set (
    PP_INSPECTOR_DEPENDENCIES
    pp_stream_splitter_iface.cc
)

set (
    PP_INSPECTOR_SOURCES
    pp_inspector.cc
    pp_inspector_iface.cc
    ${PP_INSPECTOR_DEPENDENCIES}
)

set (
    PP_IPS_OPTION_DEPENDENCIES
    pp_cursor_iface.cc
)

set (
    PP_IPS_OPTION_SOURCES
    pp_ips_option.cc
    pp_ips_option_iface.cc
    ${PP_IPS_OPTION_DEPENDENCIES}
)

set (
    PP_IPS_ACTION_SOURCES
    pp_ips_action.cc
    pp_ips_action_iface.cc
)

set (
    PP_LOGGER_SOURCES
    pp_logger.cc
    pp_logger_iface.cc
)

set (
    PP_SEARCH_ENGINE_SOURCES
    pp_search_engine.cc
    pp_search_engine_iface.cc
)

set (
    PP_SO_RULE_SOURCES
    pp_so_rule.cc
    pp_so_rule_iface.cc
)

set (
    PP_TEST_SOURCES
    pp_test.cc
)

set (
    PP_COMMON_DEPENDENCIES
    pp_raw_buffer_iface.cc
    pp_packet_iface.cc
    pp_decode_data_iface.cc
    pp_flow_iface.cc
    pp_event_iface.cc
    pp_ip_api_iface.cc
)

set (
    PP_SOURCES
    piglet_plugins.cc

    ${PP_COMMON_DEPENDENCIES}
    ${PP_CODEC_SOURCES}
    ${PP_INSPECTOR_SOURCES}
    ${PP_IPS_OPTION_SOURCES}
    ${PP_IPS_ACTION_SOURCES}
    ${PP_LOGGER_SOURCES}
    ${PP_SEARCH_ENGINE_SOURCES}
    ${PP_SO_RULE_SOURCES}
    ${PP_TEST_SOURCES}
)

add_library ( piglet_plugins OBJECT
    ${PP_SOURCES}
)
