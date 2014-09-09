AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/protocols

noinst_LIBRARIES = libprotocols.a

x_include_HEADERS = \
arp.h \
eapol.h \
eth.h \
icmp4.h \
icmp6.h \
ip.h \
ipv4.h \
ipv4_options.h \
ipv6.h \
gre.h \
layer.h \
mpls.h \
packet.h \
packet_manager.h \
protocol_ids.h \
tcp.h \
tcp_options.h \
teredo.h \
token_ring.h \
udp.h \
vlan.h \
wlan.h

libprotocols_a_SOURCES = \
layer.cc \
packet_manager.cc \
ip.cc \
ipv4_options.cc \
tcp_options.cc


AM_CXXFLAGS = @AM_CXXFLAGS@
