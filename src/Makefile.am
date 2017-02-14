
bin_PROGRAMS = snort

snort_SOURCES = \
main.cc \
main.h

if STATIC_INSPECTORS
lib_list = \
network_inspectors/arp_spoof/libarp_spoof.a \
network_inspectors/packet_capture/libpacket_capture.a \
service_inspectors/back_orifice/libback_orifice.a \
service_inspectors/dce_rpc/libdce_rpc.a \
service_inspectors/dnp3/libdnp3.a \
service_inspectors/dns/libdns.a \
service_inspectors/ftp_telnet/libftp_telnet.a \
service_inspectors/gtp/libgtp_inspect.a \
service_inspectors/modbus/libmodbus.a \
service_inspectors/rpc_decode/librpc_decode.a \
service_inspectors/ssh/libssh.a \
service_inspectors/wizard/libwizard.a
endif

if STATIC_CODECS
codec_list = \
codecs/root/libroot_codecs.a \
codecs/link/liblink_codecs.a
endif

if ENABLE_UNIT_TESTS
test_list = catch/libcatch_tests.a
endif

if ENABLE_PIGLET
pig_list = \
piglet/libpiglet.a \
piglet_plugins/libpiglet_plugins.a
endif

snort_LDFLAGS = $(SANITIZER_LDFLAGS) $(AM_LDFLAGS) -export-dynamic

# order libs to avoid undefined symbols
# from gnu linker
snort_LDADD = \
$(test_list) \
managers/libmanagers.a \
main/libmain.a \
codecs/libcodecs.a \
codecs/ip/libip_codecs.a \
codecs/misc/libmisc_codecs.a \
$(codec_list) \
loggers/libloggers.a \
network_inspectors/libnetwork_inspectors.a \
network_inspectors/appid/libappid.a \
network_inspectors/binder/libbinder.a \
network_inspectors/normalize/libnormalize.a \
network_inspectors/perf_monitor/libperf_monitor.a \
network_inspectors/reputation/libreputation.a \
service_inspectors/libservice_inspectors.a \
service_inspectors/http_inspect/libhttp_inspect.a \
service_inspectors/sip/libsip.a \
$(lib_list) \
pub_sub/libpub_sub.a \
service_inspectors/imap/libimap.a \
service_inspectors/pop/libpop.a \
service_inspectors/smtp/libsmtp.a \
service_inspectors/ssl/libssl.a \
network_inspectors/port_scan/libport_scan.a \
stream/libstream.a \
stream/base/libstream_base.a \
stream/ip/libstream_ip.a \
stream/icmp/libstream_icmp.a \
stream/tcp/libstream_tcp.a \
stream/libtcp/libstream_libtcp.a \
stream/udp/libstream_udp.a \
stream/user/libstream_user.a \
stream/file/libstream_file.a \
stream/libstream_paf.a \
mime/libmime.a \
ips_options/libips_options.a \
search_engines/libsearch_engines.a \
target_based/libtarget_based.a \
$(pig_list) \
codecs/libcodec_module.a \
memory/libmemory.a \
host_tracker/libhost_tracker.a \
parser/libparser.a \
flow/libflow.a \
control/libcontrol.a \
filters/libfilter.a \
detection/libdetection.a \
framework/libframework.a \
file_api/libfile_api.a \
latency/liblatency.a \
profiler/libprofiler.a \
time/libtime.a \
actions/libips_actions.a \
events/libevents.a \
hash/libhash.a \
log/liblog.a \
packet_io/libpacket_io.a \
helpers/libhelpers.a \
lua/liblua.a \
decompress/libdecompress.a \
sfip/libsfip.a \
sfrt/libsfrt.a \
protocols/libprotocols.a \
connectors/libconnectors.a \
connectors/file_connector/libfile_connector.a \
connectors/tcp_connector/libtcp_connector.a \
side_channel/libside_channel.a \
ports/libports.a \
utils/libutils.a

SUBDIRS = \
actions \
codecs \
control \
decompress \
detection \
events \
file_api \
filters \
flow \
framework \
hash \
helpers \
host_tracker \
latency \
lua \
ips_options \
log \
loggers \
main \
managers \
memory \
mime \
network_inspectors \
packet_io \
parser \
ports \
protocols \
pub_sub \
search_engines \
service_inspectors \
sfip \
sfrt \
side_channel \
connectors \
stream \
target_based \
time \
profiler \
utils

if ENABLE_UNIT_TESTS
SUBDIRS += catch
endif

if ENABLE_PIGLET
SUBDIRS += piglet piglet_plugins
endif
