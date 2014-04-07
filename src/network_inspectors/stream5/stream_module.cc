/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// stream_module.cc author Russ Combs <rucombs@cisco.com>

#include "stream_module.h"

#include "snort_config.h"

//-------------------------------------------------------------------------
// stream_global module
//-------------------------------------------------------------------------

static const Parameter stream_global_params[] =
{
    { "memcap", Parameter::PT_INT, "32768", "deflt",
      "8388608" },

    { "show_rebuilt_packets", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "prune_log_max", Parameter::PT_INT, "0:", "1048576",
      "help" },

    { "paf_max", Parameter::PT_INT, "1460:63780", "16384",
      "help" },

    { "track_tcp", Parameter::PT_BOOL, nullptr, "true",
      "track tcp sessions" },

    { "max_tcp", Parameter::PT_INT, "1:", "262144",
      "maximum simultaneous tcp sessions tracked before pruning" },

    { "track_udp", Parameter::PT_BOOL, nullptr, "true",
      "track udp sessions" },

    { "max_udp", Parameter::PT_INT, "1:", "131072",
      "maximum simultaneous udp sessions tracked before pruning" },

    { "track_icmp", Parameter::PT_BOOL, nullptr, "false",
      "track icmp sessions" },

    { "max_icmp", Parameter::PT_INT, "1:", "65536",
      "maximum simultaneous icmp sessions tracked before pruning" },

    { "track_ip", Parameter::PT_BOOL, nullptr, "false",
      "track ip sessions" },

    { "max_ip", Parameter::PT_INT, "1:", "16384",
      "maximum simultaneous ip sessions tracked before pruning" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap stream_global_rules[] =
{
    { 0, nullptr }
};

StreamGlobalModule::StreamGlobalModule() :
    Module("stream_global", stream_global_params, stream_global_rules) { }

bool StreamGlobalModule::set(const char*, Value&, SnortConfig*)
{
#if 0
    if ( v.is("name") )
        sc->pkt_cnt = v.get_long();

    else
        return false;
#endif
    return true;
}

bool StreamGlobalModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool StreamGlobalModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------
// stream_ip module
//-------------------------------------------------------------------------

static const Parameter stream_ip_params[] =
{
    { "timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap stream_ip_rules[] =
{
    { 0, nullptr }
};

StreamIpModule::StreamIpModule() :
    Module("stream_ip", stream_ip_params, stream_ip_rules) { }

bool StreamIpModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

bool StreamIpModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool StreamIpModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------
// stream_icmp module
//-------------------------------------------------------------------------

static const Parameter stream_icmp_params[] =
{
    { "timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap stream_icmp_rules[] =
{
    { 0, nullptr }
};

StreamIcmpModule::StreamIcmpModule() :
    Module("stream_icmp", stream_icmp_params, stream_icmp_rules) { }

bool StreamIcmpModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

bool StreamIcmpModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool StreamIcmpModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------
// stream_udp module
//-------------------------------------------------------------------------

static const Parameter stream_udp_params[] =
{
    { "timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { "ignore_any_rules", Parameter::PT_BOOL, nullptr, "false",
      "process udp content rules w/o ports only if rules with ports are present" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap stream_udp_rules[] =
{
    { 0, nullptr }
};

StreamUdpModule::StreamUdpModule() :
    Module("stream_udp", stream_udp_params, stream_udp_rules) { }

bool StreamUdpModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

bool StreamUdpModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool StreamUdpModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------
// stream_tcp module
//-------------------------------------------------------------------------

#define STREAM_TCP_SYN_ON_EST_STR \
    "(stream_tcp) Syn on established session"
#define STREAM_TCP_DATA_ON_SYN_STR \
    "(stream_tcp) Data on SYN packet"
#define STREAM_TCP_DATA_ON_CLOSED_STR \
    "(stream_tcp) Data sent on stream not accepting data"
#define STREAM_TCP_BAD_TIMESTAMP_STR \
    "(stream_tcp) TCP Timestamp is outside of PAWS window"
#define STREAM_TCP_BAD_SEGMENT_STR \
    "(stream_tcp) Bad segment, adjusted size <= 0"
#define STREAM_TCP_WINDOW_TOO_LARGE_STR \
    "(stream_tcp) Window size (after scaling) larger than policy allows"
#define STREAM_TCP_EXCESSIVE_TCP_OVERLAPS_STR \
    "(stream_tcp) Limit on number of overlapping TCP packets reached"
#define STREAM_TCP_DATA_AFTER_RESET_STR \
    "(stream_tcp) Data sent on stream after TCP Reset sent"
#define STREAM_TCP_SESSION_HIJACKED_CLIENT_STR \
    "(stream_tcp) TCP Client possibly hijacked, different Ethernet Address"
#define STREAM_TCP_SESSION_HIJACKED_SERVER_STR \
    "(stream_tcp) TCP Server possibly hijacked, different Ethernet Address"
#define STREAM_TCP_DATA_WITHOUT_FLAGS_STR \
    "(stream_tcp) TCP Data with no TCP Flags set"
#define STREAM_TCP_SMALL_SEGMENT_STR \
    "(stream_tcp) Consecutive TCP small segments exceeding threshold"
#define STREAM_TCP_4WAY_HANDSHAKE_STR \
    "(stream_tcp) 4-way handshake detected"
#define STREAM_TCP_NO_TIMESTAMP_STR \
    "(stream_tcp) TCP Timestamp is missing"
#define STREAM_TCP_BAD_RST_STR \
    "(stream_tcp) Reset outside window"
#define STREAM_TCP_BAD_FIN_STR \
    "(stream_tcp) FIN number is greater than prior FIN"
#define STREAM_TCP_BAD_ACK_STR \
    "(stream_tcp) ACK number is greater than prior FIN"
#define STREAM_TCP_DATA_AFTER_RST_RCVD_STR \
    "(stream_tcp) Data sent on stream after TCP Reset received"
#define STREAM_TCP_WINDOW_SLAM_STR \
    "(stream_tcp) TCP window closed before receiving data"
#define STREAM_TCP_NO_3WHS_STR \
    "(stream_tcp) TCP session without 3-way handshake"

static const char* policies =
    "first | last | bsd | linux | old-linux | windows | win-2003 | vista "
    "solaris | hpux | hpux10 | irix | macos";

static const char* client_ports =
    "21 23 25 42 53 80 110 111 135 136 137 139 143 445 513 514 1433 1521 "
    "2401 3306";

static const char* client_protocols =
    "ftp telnet smtp nameserver dns http pop3 sunrpc dcerpc netbios-ssn imap "
    "login shell mssql oracle cvs mysql";

static const Parameter stream_tcp_small_params[] =
{
    { "count", Parameter::PT_INT, "0:2048", "0",
      "limit number of small segments queued" },

    { "maximum_size", Parameter::PT_INT, "0:2048", "0",
      "limit number of small segments queued" },

    { "ignore_ports", Parameter::PT_BIT_LIST, "65535", "2621",
      "limit number of small segments queued" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter stream_tcp_params[] =
{
    { "both_ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "reassemble data in both directions for given server ports" },

    { "both_protocols", Parameter::PT_STRING, nullptr, nullptr,
      "reassemble data in both directions for given services" },

    { "check_session_hijacking", Parameter::PT_BOOL, nullptr, "false",
      "for ethernet, verify that segments following the syn have the same mac address" },

    { "client_ports", Parameter::PT_BIT_LIST, "65535", client_ports,
      "reassemble data from client to given server ports" },

    { "client_protocols", Parameter::PT_STRING, nullptr, client_protocols,
      "reassemble data from client for given services" },

    { "detect_anomalies", Parameter::PT_BOOL, nullptr, "false",
      "detect tcp anomalies" },

    { "dont_reassemble_async", Parameter::PT_BOOL, nullptr, "false",
      "don't queue for reassembly unless traffic is seen in both directions" },

    { "dont_store_large_packets", Parameter::PT_BOOL, nullptr, "false",
      "don't queue large packets for reassembly" },

    { "flush_factor", Parameter::PT_INT, "0:", "0",
      "flush upon seeing a drop in segment size after given number of non-decreasing segments" },

    { "ignore_any_rules", Parameter::PT_BOOL, nullptr, "false",
      "process tcp content rules w/o ports only if rules with ports are present" },

    { "max_queued_bytes", Parameter::PT_INT, "0:", "1048576",
      "don't queue more than given bytes per session and direction" },

    { "max_queued_segs", Parameter::PT_INT, "0:", "2621",
      "don't queue more than given segments per session and direction" },

    { "max_window", Parameter::PT_INT, "0:1073725440", "0",
      "maximum allowed tcp window" },

    { "overlap_limit", Parameter::PT_INT, "0:255", "0",
      "maximum number of allowed overlapping segments per session" },

    { "policy", Parameter::PT_ENUM, policies, "linux",
      "session tracking timeout" },

    { "require_3whs", Parameter::PT_INT, "0:86400", "0",
      "don't track midstream sessions after given seconds from start up" },

    { "server_ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "reassemble data from server for given server ports" },

    { "server_protocols", Parameter::PT_STRING, nullptr, nullptr,
      "reassemble data from server for given services" },

    { "small_segments", Parameter::PT_TABLE, nullptr, stream_tcp_small_params,
      "limit number of small segments queued" },

    { "timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { "use_static_footprint_sizes", Parameter::PT_BOOL, nullptr, "false",
      "for repeatable testing; not for production" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap stream_tcp_rules[] =
{
    { STREAM_TCP_SYN_ON_EST, STREAM_TCP_SYN_ON_EST_STR },
    { STREAM_TCP_DATA_ON_SYN, STREAM_TCP_DATA_ON_SYN_STR },
    { STREAM_TCP_DATA_ON_CLOSED, STREAM_TCP_DATA_ON_CLOSED_STR },
    { STREAM_TCP_BAD_TIMESTAMP, STREAM_TCP_BAD_TIMESTAMP_STR },
    { STREAM_TCP_BAD_SEGMENT, STREAM_TCP_BAD_SEGMENT_STR },
    { STREAM_TCP_WINDOW_TOO_LARGE, STREAM_TCP_WINDOW_TOO_LARGE_STR },
    { STREAM_TCP_EXCESSIVE_TCP_OVERLAPS, STREAM_TCP_EXCESSIVE_TCP_OVERLAPS_STR },
    { STREAM_TCP_DATA_AFTER_RESET, STREAM_TCP_DATA_AFTER_RESET_STR },
    { STREAM_TCP_SESSION_HIJACKED_CLIENT, STREAM_TCP_SESSION_HIJACKED_CLIENT_STR },
    { STREAM_TCP_SESSION_HIJACKED_SERVER, STREAM_TCP_SESSION_HIJACKED_SERVER_STR },
    { STREAM_TCP_DATA_WITHOUT_FLAGS, STREAM_TCP_DATA_WITHOUT_FLAGS_STR },
    { STREAM_TCP_SMALL_SEGMENT, STREAM_TCP_SMALL_SEGMENT_STR },
    { STREAM_TCP_4WAY_HANDSHAKE, STREAM_TCP_4WAY_HANDSHAKE_STR },
    { STREAM_TCP_NO_TIMESTAMP, STREAM_TCP_NO_TIMESTAMP_STR },
    { STREAM_TCP_BAD_RST, STREAM_TCP_BAD_RST_STR },
    { STREAM_TCP_BAD_FIN, STREAM_TCP_BAD_FIN_STR },
    { STREAM_TCP_BAD_ACK, STREAM_TCP_BAD_ACK_STR },
    { STREAM_TCP_DATA_AFTER_RST_RCVD, STREAM_TCP_DATA_AFTER_RST_RCVD_STR },
    { STREAM_TCP_WINDOW_SLAM, STREAM_TCP_WINDOW_SLAM_STR },
    { STREAM_TCP_NO_3WHS, STREAM_TCP_NO_3WHS_STR },

    { 0, nullptr }
};

StreamTcpModule::StreamTcpModule() :
    Module("stream_tcp", stream_tcp_params, stream_tcp_rules) { }

bool StreamTcpModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

bool StreamTcpModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool StreamTcpModule::end(const char*, int, SnortConfig*)
{
    return true;
}

