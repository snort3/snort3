
noinst_LIBRARIES = libstream.a

x_includedir = $(pkgincludedir)/stream

x_include_HEADERS = \
paf.h \
stream_api.h \
stream_splitter.h

libstream_a_SOURCES = \
flush_bucket.cc \
flush_bucket.h \
paf.cc \
stream.h \
stream_api.cc \
stream_inspectors.cc \
stream_inspectors.h \
stream_splitter.cc

# FIXIT LIBADD here causes undefineds
#libstream_a_LIBADD = \
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

