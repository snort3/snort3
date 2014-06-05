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

// cd_udp_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "cd_udp_module.h"
#include "snort_config.h"
#include "parser/config_file.h"

static const Parameter udp_params[] =
{
    { "deep_teredo_inspection", Parameter::PT_BOOL, nullptr, "false",
      "look for Teredo on all UDP ports (default is only 3544)" },

    { "enable_gtp", Parameter::PT_BOOL, nullptr, "false",
      "decode GTP encapsulations" },

    // FIXIT use PT_BIT_LIST
    { "gtp_ports", Parameter::PT_STRING, nullptr,
      "'2152 3386'", "set GTP ports" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const RuleMap udp_rules[] =
{

    { DECODE_UDP_DGRAM_LT_UDPHDR, "(" CD_UDP_NAME ") Truncated UDP Header" },
    { DECODE_UDP_DGRAM_INVALID_LENGTH, "(" CD_UDP_NAME ") Invalid UDP header, length field < 8" },
    { DECODE_UDP_DGRAM_SHORT_PACKET, "(" CD_UDP_NAME ") Short UDP packet, length field > payload length" },
    { DECODE_UDP_DGRAM_LONG_PACKET, "(" CD_UDP_NAME ") Long UDP packet, length field < payload length" },
    { DECODE_UDP_IPV6_ZERO_CHECKSUM, "(" CD_UDP_NAME ") Invalid IPv6 UDP packet, checksum zero" },
    { DECODE_UDP_LARGE_PACKET, "(" CD_UDP_NAME ") MISC Large UDP Packet" },
    { DECODE_UDP_PORT_ZERO, "(" CD_UDP_NAME ") BAD-TRAFFIC UDP port 0 traffic" },


    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

UdpModule::UdpModule() : DecodeModule(CD_UDP_NAME, udp_params, udp_rules)
{ }

bool UdpModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("deep_teredo_inspection") )
        sc->enable_teredo = v.get_long();  // FIXIT move to existing bitfield

    else if ( v.is("enable_gtp") )
    {
        if ( v.get_bool() )
            sc->enable_gtp = 1;  // FIXIT move to existing bitfield
    }
    else if ( v.is("gtp_ports") )
        ConfigGTPDecoding(sc, v.get_string());

    else
        return false;

    return true;
}
