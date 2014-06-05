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

// cd_tcp_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_tcp_module.h"


static const Parameter tcp_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap tcp_rules[] =
{
    { DECODE_TCP_DGRAM_LT_TCPHDR, "(" CD_TCP_NAME ") TCP packet len is smaller than 20 bytes" },
    { DECODE_TCP_INVALID_OFFSET, "(" CD_TCP_NAME ") TCP Data Offset is less than 5" },
    { DECODE_TCP_LARGE_OFFSET, "(" CD_TCP_NAME ") TCP Header length exceeds packet length" },

    { DECODE_TCPOPT_BADLEN, "(" CD_TCP_NAME ") Tcp Options found with bad lengths" },
    { DECODE_TCPOPT_TRUNCATED, "(" CD_TCP_NAME ") Truncated Tcp Options" },
    { DECODE_TCPOPT_TTCP, "(" CD_TCP_NAME ") T/TCP Detected" },
    { DECODE_TCPOPT_OBSOLETE, "(" CD_TCP_NAME ") Obsolete TCP Options found" },
    { DECODE_TCPOPT_EXPERIMENTAL, "(" CD_TCP_NAME ") Experimental Tcp Options found" },
    { DECODE_TCPOPT_WSCALE_INVALID, "(" CD_TCP_NAME ") Tcp Window Scale Option found with length > 14" },
    { DECODE_TCP_XMAS, "(" CD_TCP_NAME ") XMAS Attack Detected" },
    { DECODE_TCP_NMAP_XMAS, "(" CD_TCP_NAME ") Nmap XMAS Attack Detected" },
    { DECODE_TCP_BAD_URP, "(" CD_TCP_NAME ") TCP urgent pointer exceeds payload length or no payload" },
    { DECODE_TCP_SYN_FIN, "(" CD_TCP_NAME ") TCP SYN with FIN" },
    { DECODE_TCP_SYN_RST, "(" CD_TCP_NAME ") TCP SYN with RST" },
    { DECODE_TCP_MUST_ACK, "(" CD_TCP_NAME ") TCP PDU missing ack for established session" },
    { DECODE_TCP_NO_SYN_ACK_RST, "(" CD_TCP_NAME ") TCP has no SYN, ACK, or RST" },
    { DECODE_TCP_SHAFT_SYNFLOOD, "(" CD_TCP_NAME ") DDOS shaft synflood" },
    { DECODE_TCP_PORT_ZERO, "(" CD_TCP_NAME ") BAD-TRAFFIC TCP port 0 traffic" },
    { DECODE_DOS_NAPTHA, "(decode) DOS NAPTHA Vulnerability Detected" },
    { DECODE_SYN_TO_MULTICAST, "(decode) Bad Traffic SYN to multicast address" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

TcpModule::TcpModule() : DecodeModule(CD_TCP_NAME, tcp_params, tcp_rules)
{ }

bool TcpModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}
