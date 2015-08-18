
noinst_LIBRARIES = libpiglet_plugins.a

libpiglet_plugins_a_SOURCES = \
piglet_plugins.cc \
piglet_plugins.h

interface_list = \
pp_codec_data_iface.cc \
pp_enc_state_iface.cc \
pp_buffer_iface.cc \
pp_event_iface.cc \
pp_codec_iface.cc \
pp_stream_splitter_iface.cc \
pp_inspector_iface.cc \
pp_cursor_iface.cc \
pp_ips_option_iface.cc \
pp_ips_action_iface.cc \
pp_logger_iface.cc \
pp_search_engine_iface.cc \
pp_so_rule_iface.cc \
pp_raw_buffer_iface.cc \
pp_packet_iface.cc \
pp_decode_data_iface.cc \
pp_flow_iface.cc \
pp_event_iface.cc \
pp_daq_pkthdr_iface.cc \
pp_ip_api_iface.cc

plugin_list = \
pp_codec.cc \
pp_inspector.cc \
pp_ips_action.cc \
pp_ips_option.cc \
pp_logger.cc \
pp_search_engine.cc \
pp_so_rule.cc \
pp_test.cc

libpiglet_plugins_a_SOURCES += $(plugin_list)
libpiglet_plugins_a_SOURCES += $(interface_list)

AM_CXXFLAGS = @AM_CXXFLAGS@
