AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = snort

snort_includedir = $(pkgincludedir)

snort_include_HEADERS = \
thread.h \
snort_debug.h \
snort_types.h

snort_SOURCES = \
snort.cc snort.h \
snort_debug.cc \
snort_config.cc snort_config.h \
analyzer.cc analyzer.h \
policy.cc policy.h \
main.cc main.h \
build.h

if STATIC_INSPECTORS
lib_list = \
network_inspectors/arp_spoof/libarp_spoof.a \
network_inspectors/port_scan/libport_scan.a \
service_inspectors/back_orifice/libback_orifice.a \
service_inspectors/ftp_telnet/libftp_telnet.a \
service_inspectors/rpc_decode/librpc_decode.a
endif

# order libs to avoid undefined symbols
snort_LDADD = \
target_based/libtarget_based.a \
file_api/libfile_api.a \
file_api/libs/libfile.a \
managers/libmanagers.a \
parser/libparser.a \
loggers/libloggers.a \
codecs/libcodecs.a \
codecs/basic/libbasic_codecs.a \
network_inspectors/libnetwork_inspectors.a \
network_inspectors/defrag/libdefrag.a \
network_inspectors/normalize/libnormalize.a \
network_inspectors/perf_monitor/libperf_monitor.a \
network_inspectors/stream5/libstream.a \
network_inspectors/stream5/libstream_api.a \
service_inspectors/libservice_inspectors.a \
service_inspectors/http_inspect/libhttp_inspect.a \
$(lib_list) \
ips_options/libips_options.a \
search_engines/libsearch_engines.a \
framework/libframework.a \
protocols/libprotocols.a \
flow/libflow.a \
control/libcontrol.a \
filters/libfilter.a \
detection/libdetection.a \
time/libtime.a \
actions/libactions.a \
events/libevents.a \
hash/libhash.a \
mempool/libmempool.a \
log/liblog.a \
packet_io/libpacket_io.a \
helpers/libhelpers.a \
sfip/libsfip.a \
sfrt/libsfrt.a \
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
managers \
mempool \
network_inspectors \
packet_io \
parser \
protocols \
search_engines \
service_inspectors \
sfip \
sfrt \
target_based \
time \
utils

AM_CXXFLAGS = @AM_CXXFLAGS@

if BUILD_UNIT_TESTS
snort_LDADD += test/libtest.a
SUBDIRS += test
endif

if BUILD_SIDE_CHANNEL
snort_LDADD += \
side_channel/libsidechannel.a \
side_channel/plugins/libsscm.a
SUBDIRS += side_channel
endif

