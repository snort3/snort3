
noinst_LIBRARIES = \
libstream.a \
libstream_paf.a

x_includedir = $(pkgincludedir)/stream

x_include_HEADERS = \
paf.h \
stream.h \
stream_splitter.h

libstream_a_SOURCES = \
stream.cc \
stream_inspectors.cc \
stream_inspectors.h \
stream_splitter.cc

libstream_paf_a_SOURCES = \
flush_bucket.cc \
flush_bucket.h \
paf.cc

# FIXIT LIBADD here causes undefineds
#libstream_a_LIBADD = \
#libstream_paf_a_LIBADD = \
#base/libstream_base.a
#ip/libstream_ip.a
#icmp/libstream_icmp.a
#libtcp/libstream_libtcp.a
#tcp/libstream_tcp.a
#udp/libstream_udp.a
#user/libstream_user.a
#file/libstream_file.a

SUBDIRS = \
base \
ip \
icmp \
libtcp \
tcp \
udp \
user \
file

if BUILD_CPPUTESTS
SUBDIRS += test
endif

