AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = snort

snort_SOURCES = \
main.cc \
main.h

if STATIC_INSPECTORS
lib_list = \
network_inspectors/arp_spoof/libarp_spoof.a \
network_inspectors/port_scan/libport_scan.a \
service_inspectors/back_orifice/libback_orifice.a \
service_inspectors/ftp_telnet/libftp_telnet.a \
service_inspectors/nhttp_inspect/libnhttp_inspect.a \
service_inspectors/rpc_decode/librpc_decode.a \
service_inspectors/wizard/libwizard.a
endif

if STATIC_CODECS
codec_list = \
codecs/root/libroot_codecs.a \
codecs/link/liblink_codecs.a
endif

# order libs to avoid undefined symbols
# from gnu linker
snort_LDADD = \
target_based/libtarget_based.a \
managers/libmanagers.a \
main/libmain.a \
loggers/libloggers.a \
codecs/libcodecs.a \
codecs/ip/libip_codecs.a \
codecs/misc/libmisc_codecs.a \
${codec_list} \
codecs/libcodec_utils.a \
network_inspectors/libnetwork_inspectors.a \
network_inspectors/binder/libbinder.a \
network_inspectors/normalize/libnormalize.a \
network_inspectors/perf_monitor/libperf_monitor.a \
service_inspectors/libservice_inspectors.a \
service_inspectors/http_inspect/libhttp_inspect.a \
$(lib_list) \
stream/base/libstream_base.a \
stream/ip/libstream_ip.a \
stream/icmp/libstream_icmp.a \
stream/tcp/libstream_tcp.a \
stream/udp/libstream_udp.a \
stream/libstream.a \
file_api/libfile_api.a \
file_api/libs/libfile.a \
ips_options/libips_options.a \
parser/libparser.a \
search_engines/libsearch_engines.a \
flow/libflow.a \
control/libcontrol.a \
filters/libfilter.a \
detection/libdetection.a \
framework/libframework.a \
time/libtime.a \
actions/libips_actions.a \
events/libevents.a \
hash/libhash.a \
log/liblog.a \
packet_io/libpacket_io.a \
helpers/libhelpers.a \
sfip/libsfip.a \
sfrt/libsfrt.a \
protocols/libprotocols.a \
utils/libutils.a

SUBDIRS = \
actions \
codecs \
control \
detection \
events \
file_api \
filters \
flow \
framework \
hash \
helpers \
ips_options \
log \
loggers \
main \
managers \
network_inspectors \
packet_io \
parser \
protocols \
search_engines \
service_inspectors \
sfip \
sfrt \
stream \
target_based \
time \
utils

AM_CXXFLAGS = @AM_CXXFLAGS@

if BUILD_UNIT_TESTS
snort_LDADD += test/libtest.a
SUBDIRS += test
endif

