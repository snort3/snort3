
AM_CPPFLAGS+=-I$(top_srcdir)/src/network_inspectors/appid
AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = \
appid_simple_test \
process_http_test

TESTS = $(check_PROGRAMS)

lib_list = \
../../../network_inspectors/arp_spoof/libarp_spoof.a \
../../../network_inspectors/packet_capture/libpacket_capture.a \
../../../service_inspectors/back_orifice/libback_orifice.a \
../../../service_inspectors/dce_rpc/libdce_rpc.a \
../../../service_inspectors/dnp3/libdnp3.a \
../../../service_inspectors/dns/libdns.a \
../../../service_inspectors/ftp_telnet/libftp_telnet.a \
../../../service_inspectors/gtp/libgtp_inspect.a \
../../../service_inspectors/modbus/libmodbus.a \
../../../service_inspectors/http_inspect/libhttp_inspect.a \
../../../service_inspectors/rpc_decode/librpc_decode.a \
../../../service_inspectors/sip/libsip.a \
../../../service_inspectors/ssh/libssh.a \
../../../service_inspectors/wizard/libwizard.a

if STATIC_CODECS
codec_list = \
../../../codecs/root/libroot_codecs.a \
../../../codecs/link/liblink_codecs.a
endif


test_list = ../../../catch/libcatch_tests.a

if ENABLE_PIGLET
pig_list = \
piglet/libpiglet.a \
piglet_plugins/libpiglet_plugins.a
endif

# order libs to avoid undefined symbols
# from gnu linker
snort_LIBS = \
$(test_list) \
../../../managers/libmanagers.a \
../../../loggers/libloggers.a \
../../../codecs/libcodecs.a \
../../../codecs/ip/libip_codecs.a \
../../../codecs/misc/libmisc_codecs.a \
$(codec_list) \
../../../network_inspectors/libnetwork_inspectors.a \
../../../network_inspectors/binder/libbinder.a \
../../../network_inspectors/normalize/libnormalize.a \
../../../network_inspectors/perf_monitor/libperf_monitor.a \
../../../network_inspectors/reputation/libreputation.a \
../../../network_inspectors/appid/libappid.a \
../../../network_inspectors/appid/client_plugins/libclient_plugins.a \
../../../network_inspectors/appid/detector_plugins/libdetector_plugins.a \
../../../network_inspectors/appid/service_plugins/libservice_plugins.a \
../../../network_inspectors/appid/util/libappidutil.a \
../../../service_inspectors/libservice_inspectors.a \
$(lib_list) \
../../../service_inspectors/imap/libimap.a \
../../../service_inspectors/pop/libpop.a \
../../../service_inspectors/smtp/libsmtp.a \
../../../service_inspectors/ssl/libssl.a \
../../../network_inspectors/port_scan/libport_scan.a \
../../../stream/libstream.a \
../../../stream/base/libstream_base.a \
../../../stream/ip/libstream_ip.a \
../../../stream/icmp/libstream_icmp.a \
../../../stream/tcp/libstream_tcp.a \
../../../stream/libtcp/libstream_libtcp.a \
../../../stream/udp/libstream_udp.a \
../../../stream/user/libstream_user.a \
../../../stream/file/libstream_file.a \
../../../stream/libstream_paf.a \
../../../file_api/libfile_api.a \
../../../mime/libmime.a \
../../../service_inspectors/http_inspect/libhttp_inspect.a \
$(pig_list) \
../../../ips_options/libips_options.a \
../../../search_engines/libsearch_engines.a \
../../../target_based/libtarget_based.a \
../../../main/libmain.a \
../../../codecs/libcodec_module.a \
../../../memory/libmemory.a \
../../../host_tracker/libhost_tracker.a \
../../../parser/libparser.a \
../../../flow/libflow.a \
../../../control/libcontrol.a \
../../../filters/libfilter.a \
../../../detection/libdetection.a \
../../../framework/libframework.a \
../../../time/libtime.a \
../../../latency/liblatency.a \
../../../profiler/libprofiler.a \
../../../actions/libips_actions.a \
../../../events/libevents.a \
../../../hash/libhash.a \
../../../log/liblog.a \
../../../packet_io/libpacket_io.a \
../../../helpers/libhelpers.a \
../../../lua/liblua.a \
../../../decompress/libdecompress.a \
../../../sfip/libsfip.a \
../../../sfrt/libsfrt.a \
../../../protocols/libprotocols.a \
../../../connectors/libconnectors.a \
../../../connectors/file_connector/libfile_connector.a \
../../../side_channel/libside_channel.a \
../../../ports/libports.a \
../../../utils/libutils.a

appid_simple_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
appid_simple_test_LDADD = ${snort_LIBS} @CPPUTEST_LDFLAGS@
process_http_test_CPPFLAGS = $(AM_CPPFLAGS) @CPPUTEST_CPPFLAGS@
process_http_test_LDADD = ${snort_LIBS} @CPPUTEST_LDFLAGS@


