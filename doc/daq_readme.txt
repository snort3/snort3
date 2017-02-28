Snort 2.9 introduces the DAQ, or Data Acquisition library, for packet I/O.  The
DAQ replaces direct calls to libpcap functions with an abstraction layer that
facilitates operation on a variety of hardware and software interfaces without
requiring changes to Snort.  It is possible to select the DAQ type and mode
when invoking Snort to perform pcap readback or inline operation, etc.  The
DAQ library may be useful for other packet processing applications and the
modular nature allows you to build new modules for other platforms.

This README summarizes the important things you need to know to use the DAQ.


==== Building the DAQ Library and DAQ Modules

The DAQ is bundled with Snort but must be built first using these steps:

    ./configure
    make
    sudo make install

This will build and install both static and dynamic DAQ modules.

Note that pcap >= 1.5.0 is required.  pcap 1.8.1 is available at the time
of this writing and is recommended.

Also, libdnet is required for IPQ and NFQ DAQs.  If you get a relocation error
trying to build those DAQs, you may need to reinstall libdnet and configure it
with something like this:

    ./configure "CFLAGS=-fPIC -g -O2"

You may also experience problems trying to find the dynamic dnet library
because it isn't always named properly.  Try creating a link to the shared
library (identified by its .x or .x.y etc. extension) with the same name but
with ".so" inserted as follows:

    $ ln -s libdnet.1.1 libdnet.so.1.1
    $ ldconfig -Rv /usr/local/lib 2>&1 | grep dnet
      Adding /usr/local/lib/libdnet.so.1.1

Alternatively, you should be able to fix both issues as follows:

    libtoolize --copy --force
    aclocal -I config
    autoheader
    autoconf
    automake --foreign

When the DAQ library is built, both static and dynamic flavors will be
generated.  The various DAQ modules will be built if the requisite headers and
libraries are available.  You can disable individual modules, etc. with options
to configure.  For the complete list of configure options, run:

    ./configure --help


==== PCAP Module

pcap is the default DAQ.  If snort is run w/o any DAQ arguments, it will
operate as it always did using this module.  These are equivalent:

    ./snort -i <device>
    ./snort -r <file>

    ./snort --daq pcap --daq-mode passive -i <device>
    ./snort --daq pcap --daq-mode read-file -r <file>

You can specify the buffer size pcap uses with:

    ./snort --daq pcap --daq-var buffer_size=<#bytes>

Immediate (less-buffered or unbuffered) delivery mode can be enabled with:

    ./snort --daq pcap --daq-var immediate=1

This immediate delivery mode can be particularly useful on modern Linux systems
with TPACKET_V3 support.  LibPCAP will attempt to use this mode when it is
available, but it introduces some potentially undesirable behavior in exchange
for better performance.  The most notable behavior change is that the packet
timeout will never occur if packets are not being received, causing the poll()
to potentially hang indefinitely.  Enabling immediate delivery mode will cause
LibPCAP to use TPACKET_V2 instead of TPACKET_V3.

* The pcap DAQ does not count filtered packets. *


==== AFPACKET Module

afpacket functions similar to the pcap DAQ but with better performance:

    ./snort --daq afpacket -i <device>
            [--daq-var buffer_size_mb=<#MB>]
            [--daq-var debug]

If you want to run afpacket in inline mode, you must craft the device string as
one or more interface pairs, where each member of a pair is separated by a
single colon and each pair is separated by a double colon like this:

    eth0:eth1

or this:

    eth0:eth1::eth2:eth3

By default, the afpacket DAQ allocates 128MB for packet memory.  You can change
this with:

    --daq-var buffer_size_mb=<#MB>

Note that the total allocated is actually higher, here's why.  Assuming the
default packet memory with a snaplen of 1518, the numbers break down like this:

* The frame size is 1518 (snaplen) + the size of the AFPacket header (66
  bytes) = 1584 bytes.

* The number of frames is 128 MB / 1518 = 84733.

* The smallest block size that can fit at least one frame is  4 KB = 4096 bytes
  @ 2 frames per block.

* As a result, we need 84733 / 2 = 42366 blocks.

* Actual memory allocated is 42366 * 4 KB = 165.5 MB.

NOTE: Linux kernel version 2.6.31 or higher is required for the AFPacket DAQ
module due to its dependency on both TPACKET v2 and PACKET_TX_RING support.

===== Fanout (Kernel Loadbalancing)

More recent Linux kernel versions (3.1+) support various kernel-space
loadbalancing methods within AFPacket configured using the PACKET_FANOUT ioctl.
This allows you to have multiple AFPacket DAQ module instances processing
packets from the same interfaces in parallel for significantly improved
throughput.

To configure PACKET_FANOUT in the AFPacket DAQ module, two DAQ variables are
used:

    --daq-var fanout_type=<hash|lb|cpu|rollover|rnd|qm>

and (optionally):

    --daq-var fanout_flag=<rollover|defrag>

In general, you're going to want to use the 'hash' fanout type, but the others
have been included for completeness.  The 'defrag' fanout flag is probably a
good idea to correctly handle loadbalancing of flows containing fragmented
packets.

Please read the man page for 'packet' or packet_mmap.txt in the Linux kernel
source for more details on the different fanout types and modifier flags.


==== NFQ Module

NFQ is the new and improved way to process iptables packets:

    ./snort --daq nfq \
        [--daq-var device=<dev>] \
        [--daq-var proto=<proto>] \
        [--daq-var queue=<qid>]

    <dev> ::= ip | eth0, etc; default is IP injection
    <proto> ::= ip4 | ip6 |; default is ip4
    <qid> ::= 0..65535; default is 0

This module can not run unprivileged so ./snort -u -g will produce a warning
and won't change user or group.

Notes on iptables are given below.


==== IPQ Module

IPQ is the old way to process iptables packets.  It replaces the inline version
available in pre-2.9 versions built with this:

    ./configure --enable-inline

Note that layer 2 resets are not supported with the IPQ DAQ:

    config layer2resets[: <mac>]

Start the IPQ DAQ as follows:

    ./snort --daq ipq \
        [--daq-var device=<dev>] \
        [--daq-var proto=<proto>] \

    <dev> ::= ip | eth0, etc; default is IP injection
    <proto> ::= ip4 | ip6; default is ip4

This module can not run unprivileged so ./snort -u -g will produce a warning
and won't change user or group.

Notes on iptables are given below.


==== IPFW Module

IPFW is available for BSD systems.  It replaces the inline version available in
pre-2.9 versions built with this:

    ./configure --enable-ipfw

This command line argument is no longer supported:

    ./snort -J <port#>

Instead, start Snort like this:

    ./snort --daq ipfw [--daq-var port=<port>]

    <port> ::= 1..65535; default is 8000

* IPFW only supports ip4 traffic.

Notes on FreeBSD and OpenBSD are given below.


==== Dump Module

The dump DAQ allows you to test the various inline mode features available in
2.9 Snort like injection and normalization.

    ./snort -i <device> --daq dump
    ./snort -r <pcap> --daq dump

By default a file named inline-out.pcap will be created containing all packets
that passed through or were generated by snort.  You can optionally specify a
different name.

    ./snort --daq dump --daq-var file=<name>

The dump DAQ also supports text output of verdicts rendered, injected packets,
and other such items.  In order to enable text output, the 'output' DAQ
variable must be set to either 'text' (text output only) or 'both' (both text
and PCAP output will be written). The default filename for the text output is
inline-out.txt, but it can be overridden like so:

    ./snort --daq dump --daq-var output=text --daq-var text-file=<filename>

dump uses the pcap daq for packet acquisition.  It therefore does not count
filtered packets (a pcap limitation).

Note that the dump DAQ inline mode is not an actual inline mode.  Furthermore,
you will probably want to have the pcap DAQ acquire in another mode like this:

    ./snort -r <pcap> -Q --daq dump --daq-var load-mode=read-file
    ./snort -i <device> -Q --daq dump --daq-var load-mode=passive


==== Netmap Module

The netmap project is a framework for very high speed packet I/O.  It is
available on both FreeBSD and Linux with varying amounts of preparatory
setup required.  Specific notes for each follow.

    ./snort --daq netmap -i <device>
            [--daq-var debug]

If you want to run netmap in inline mode, you must craft the device string as
one or more interface pairs, where each member of a pair is separated by a
single colon and each pair is separated by a double colon like this:

    em1:em2

or this:

    em1:em2::em3:em4

Inline operation performs Layer 2 forwarding with no MAC filtering, akin to the
AFPacket module's behavior.  All packets received on one interface in an inline
pair will be forwarded out the other interface unless dropped by the reader and
vice versa.

IMPORTANT: The interfaces will need to be up and in promiscuous mode in order to
function ('ifconfig em1 up promisc').  The DAQ module does not currently do
either of these configuration steps for itself.

===== FreeBSD

In FreeBSD 10.0, netmap has been integrated into the core OS.  In order to use
it, you must recompile your kernel with the line

    device netmap

added to your kernel config.

===== Linux

You will need to download the netmap source code from the project's repository:

    https://code.google.com/p/netmap/

Follow the instructions on the project's homepage for compiling and installing
the code:

    http://info.iet.unipi.it/~luigi/netmap/

It will involve a standalone kernel module (netmap_lin) as well as patching and
rebuilding the kernel module used to drive your network adapters. The following
drivers are supported under Linux at the time of writing (June 2014):

    e1000
    e1000e
    forcedeth
    igb
    ixgbe
    r8169
    virtio

TODO:
- Support for attaching to only a single ring (queue) on a network adapter.
- Support for VALE and netmap pipes.


==== Notes on iptables

These notes are just a quick reminder that you need to set up iptables to use
the IPQ or NFQ DAQs.  Doing so may cause problems with your network so tread
carefully.  The examples below are intentionally incomplete so please read the
related documentation first.

Here is a blog post by Marty for historical reference:

    http://archives.neohapsis.com/archives/snort/2000-11/0394.html

You can check this out for queue sizing tips:

    http://www.inliniac.net/blog/2008/01/23/improving-snort_inlines-nfq-performance.html

You might find useful IPQ info here:

    http://snort-inline.sourceforge.net/

Use this to examine your iptables:

    sudo /sbin/iptables -L

Use something like this to set up NFQ:

    sudo /sbin/iptables
        -I <table> [<protocol stuff>] [<state stuff>]
        -j NFQUEUE --queue-num 1

Use something like this to set up IPQ:

    sudo iptables -I FORWARD -j QUEUE

Use something like this to "disconnect" snort:

    sudo /sbin/iptables -D <table> <rule pos>

Be sure to start Snort prior to routing packets through NFQ with iptables.
Such packets will be dropped until Snort is started.

The queue-num is the number you must give Snort.

If you are running on a system with both NFQ and IPQ support, you may
experience some start-up failures of the sort:

The solution seems to be to remove both modules from the kernel like this:

    modprobe -r nfnetlink_queue
    modprobe -r ip_queue

and then install the module you want:

    modprobe ip_queue

or:

    modprobe nfnetlink_queue

These DAQs should be run with a snaplen of 65535 since the kernel defrags the
packets before queuing.  Also, no need to configure frag3.


==== Notes on FreeBSD::IPFW

Check the online manual at:

    http://www.freebsd.org/doc/handbook/firewalls-ipfw.html.

Here is a brief example to divert icmp packets to Snort at port 8000:

To enable support for divert sockets, place the following lines in the
kernel configuration file:

    options IPFIREWALL
    options IPDIVERT

(The file in this case was: /usr/src/sys/i386/conf/GENERIC; which is platform
dependent.)

You may need to also set these to use the loadable kernel modules:

    /etc/rc.conf:
    firewall_enable="YES"

    /boot/loader.conf:
    ipfw_load="YES"
    ipdivert_load="YES"

    $ dmesg | grep ipfw
    ipfw2 (+ipv6) initialized, divert loadable, nat loadable, rule-based
    forwarding disabled, default to deny, logging disabled

    $ kldload -v ipdivert
    Loaded ipdivert, id=4

    $ ipfw add 75 divert 8000 icmp from any to any
    00075 divert 8000 icmp from any to any

    $ ipfw list
    ...
    00075 divert 8000 icmp from any to any
    00080 allow icmp from any to any
    ...

* Note that on FreeBSD, divert sockets don't work with bridges!

Please refer to the following articles for more information:

https://forums.snort.org/forums/support/topics/snort-inline-on-freebsd-ipfw
http://freebsd.rogness.net/snort_inline/

NAT gateway can be used with divert sockets if the network environment is
conducive to using NAT.

The steps to set up NAT with ipfw are as follows:

1. Set up NAT with two interface em0 and em1 by adding the following to
/etc/rc.conf.  Here em0 is connected to external network and em1 to host-only
LAN.


    gateway_enable="YES"
    natd_program="/sbin/natd"   # path to natd
    natd_enable="YES"           # Enable natd (if firewall_enable == YES)
    natd_interface="em0"       # Public interface or IP Address
    natd_flags="-dynamic"       # Additional flags
    defaultrouter=""
    ifconfig_em0="DHCP"
    ifconfig_em1="inet 192.168.1.2 netmask 255.255.255.0"
    firewall_enable="YES"
    firewall_script="/etc/rc.firewall"
    firewall_type="simple"

2. Add the following divert rules to divert packets to Snort above and
below the NAT rule in the "Simple" section of /etc/rc.firewall.

   ...
   # Inspect outbound packets (those arriving on "inside" interface)
   # before NAT translation.
   ${fwcmd} add divert 8000 all from any to any in via ${iif}
   case ${natd_enable} in
   [Yy][Ee][Ss])
       if [ -n "${natd_interface}" ]; then
           ${fwcmd} add divert natd all from any to any via
${natd_interface}
       fi
       ;;
   esac
   ...
   # Inspect inbound packets (those arriving on "outside" interface)
   # after NAT translation that aren't blocked for other reasons,
   # after the TCP "established" rule.
   ${fwcmd} add divert 8000 all from any to any in via ${oif}


==== Notes on OpenBSD::IPFW

OpenBSD supports divert sockets as of 4.7, so we use the ipfw DAQ.

Here is one way to set things up:

1.  Configure the system to forward packets:

    $ sysctl net.inet.ip.forwarding=1
    $ sysctl net.inet6.ip6.forwarding=1

    (You can also put that in /etc/sysctl.conf to enable on boot.)

2.  Set up interfaces

    $ dhclient vic1
    $ dhclient vic2

3.  Set up packet filter rules:

    $ echo "pass out on vic1 divert-packet port 9000 keep-state" > rules.txt
    $ echo "pass out on vic2 divert-packet port 9000 keep-state" >> rules.txt

    $ pfctl -v -f rules.txt

4.  Analyze packets diverted to port 9000:

    $ ./snort --daq ipfw --daq-var port=9000

* Note that on OpenBSD, divert sockets don't work with bridges!

