//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// dump_flows_descriptor.h author davis mcpherson <davmcphe@cisco.com>

#ifndef DUMP_FLOWS_DESCRIPTOR_H
#define DUMP_FLOWS_DESCRIPTOR_H

#include <cstdint>
#include <fstream>

#include "framework/decode_data.h"
#include "sfip/sf_ip.h"

static const char* const statext[] =
{
    "LST", "SYS", "SYR", "EST", "MDS", "MDR", "FW1", "FW2", "CLW",
    "CLG", "LAK", "TWT", "CLD", "NON"
};

static const char* stream_tcp_state_to_str(uint8_t tcp_state)
{
    if (tcp_state >= sizeof(statext) / sizeof(statext[0]))
        return "NON";

    return statext[tcp_state];
}

static std::string timeout_to_str(time_t t)
{
    std::stringstream out;
    time_t hours = t / (60 * 60);

    if (hours)
    {
        out << hours << "h";
        t -= hours * (60 * 60);
    }

    time_t minutes = t / 60;
    if (minutes || hours)
    {
        out << minutes << "m";
        t -= minutes * 60;
    }

    if (t || !hours)
        out << t << "s";

    return out.str();
}

static bool is_ip_match(const snort::SfIp& flow_sfip, const snort::SfIp& filter_sfip, const snort::SfIp& filter_subnet_sfip)
{
    //if address is empty
    if ( !filter_sfip.is_set() )
        return true;

    //if no subnet mask
    if ( !filter_subnet_sfip.is_set() )
        return filter_sfip.fast_equals_raw(flow_sfip);
    else
    {
        if (filter_sfip.get_family() != flow_sfip.get_family())
            return false;

        const uint64_t* filter_ptr = filter_sfip.get_ip64_ptr();
        const uint64_t* flow_ptr = flow_sfip.get_ip64_ptr();
        const uint64_t* subnet_sfip = filter_subnet_sfip.get_ip64_ptr();
        return (filter_ptr[0] & subnet_sfip[0]) == (flow_ptr[0] & subnet_sfip[0]) && (filter_ptr[1] & subnet_sfip[1]) == (flow_ptr[1] & subnet_sfip[1]);
    }
}

class DumpFlowsFilter
{
public:
    DumpFlowsFilter(bool binary_output)
        : binary_output(binary_output)
    { }
    virtual ~DumpFlowsFilter() {}

    virtual bool filter_flow(const snort::SfIp& , const snort::SfIp&, uint16_t, uint16_t, PktType = PktType::NONE)
    { return true; }

    static void cidr2mask(uint32_t cidr, uint32_t* mask)
    {
        while( cidr-- )
            mask[cidr / 32] |= (unsigned)0x00000001 << (cidr % 32);
    }

    bool set_ip(const std::string& ip, snort::SfIp& filter_ip, snort::SfIp& filter_subnet) const
    {
        size_t slash_pos = ip.find('/');
        if ( slash_pos != std::string::npos )
        {
            std::string ip_addr = ip.substr(0, slash_pos);
            std::string ip_subnet = ip.substr(slash_pos + 1);

            if ( ip_addr.find(':') != std::string::npos )
            {
                // filter is IPV6
                if ( filter_ip.pton(AF_INET6, ip_addr.c_str()) != SFIP_SUCCESS )
                    return false;

                if  (ip_subnet.find(':') == std::string::npos )
                {
                    // IPV6 cidr
                    uint32_t mask_v6[4] = {0};
                    uint32_t cidr = std::stoi(ip_subnet);
                    if ( cidr > 128 )
                        return false;

                    cidr2mask(cidr, mask_v6);
                    if ( filter_subnet.set(&mask_v6, AF_INET6) != SFIP_SUCCESS )
                        return false;
                }
                else if ( ip_subnet.empty() || (filter_subnet.pton(AF_INET6, ip_subnet.c_str()) != SFIP_SUCCESS) )
                    return false;

                return true;
            }
            else if ( ip_addr.find('.') != std::string::npos )
            {
                // filter is  IPV4
                if ( filter_ip.pton(AF_INET, ip_addr.c_str()) != SFIP_SUCCESS )
                    return false;

                if ( ip_subnet.find('.') == std::string::npos )
                {
                    // IPV4 cidr
                    uint32_t mask_v4[1] = {0};
                    uint32_t cidr = std::stoi(ip_subnet);
                    if ( cidr > 32 )
                        return false;

                    cidr2mask(cidr, mask_v4);
                    if ( filter_subnet.set(&mask_v4, AF_INET) != SFIP_SUCCESS )
                        return false;
                }
                else if ( ip_subnet.empty() )
                    return false;
                else
                {
                    // IPV4 netmask
                    if ( filter_subnet.pton(AF_INET, ip_subnet.c_str()) != SFIP_SUCCESS )
                        return false;
                }

                return true;
            }

            return false;
        }
        else
        {
            // No mask
            if ( ip.find(':') != std::string::npos )
                return filter_ip.pton(AF_INET6, ip.c_str()) == SFIP_SUCCESS;
            else if ( ip.find('.') != std::string::npos )
                return filter_ip.pton(AF_INET, ip.c_str()) == SFIP_SUCCESS;
        }

        return false;
    }

     bool set_ipA(const std::string& ip)
     {
        if ( ip.empty() )
            return true;

        filter_none = false;
        return set_ip(ip, ipA, ipA_subnet);
     }

     bool set_ipB(const std::string& ip)
     {
        if ( ip.empty() )
            return true;

        filter_none = false;
        return set_ip(ip, ipB, ipB_subnet);
     }

     void set_portA(uint16_t filter_port)
     { 
        filter_none = false;
        portA = filter_port;
     }

     void set_portB(uint16_t filter_port) 
     { 
        filter_none = false; 
        portB = filter_port;
     }

    bool binary_output = false;
    unsigned count = 100;
    bool filter_none = true;
    PktType proto_type = PktType::NONE;
    snort::SfIp ipA;
    snort::SfIp ipB;
    snort::SfIp ipA_subnet;
    snort::SfIp ipB_subnet;
	uint16_t portA = 0;
	uint16_t portB = 0;

    std::string file_name;
    int resume = -1;

};

class DumpFlowsFilterAnd : public DumpFlowsFilter
{
public:

    DumpFlowsFilterAnd(bool enable_binary_output)
        : DumpFlowsFilter(enable_binary_output)
    { }

    ~DumpFlowsFilterAnd() override
    { }

    bool filter_flow(const snort::SfIp& server_ip, const snort::SfIp& client_ip, 
        uint16_t server_port, uint16_t client_port, PktType = PktType::NONE) override
    {
        if ( portA != 0 and portA != server_port )
            return false;

        if ( portB != 0 and portB != client_port )
            return false;

        if ( !ipA.is_set() and !ipB.is_set() )
            return true;

        if ( ipA.is_set() and !is_ip_match(server_ip, ipA, ipA_subnet) )
            return false;

        if ( ipB.is_set() and !is_ip_match(client_ip, ipB, ipB_subnet) )
            return false;

        return true;
    }
};

class DumpFlowsFilterOr : public DumpFlowsFilter
{
public:

    DumpFlowsFilterOr(bool enable_binary_output)
        : DumpFlowsFilter(enable_binary_output)
    { }

    ~DumpFlowsFilterOr() override
    { }

    bool filter_flow(const snort::SfIp& server_ip, const snort::SfIp& client_ip, 
        uint16_t server_port, uint16_t client_port, PktType = PktType::NONE) override
    {

        if ( ipA.is_set() )
        {
            if ( ipB.is_set() )
            {
                if ( is_ip_match(server_ip, ipA, ipA_subnet) and is_ip_match(client_ip, ipB, ipB_subnet) )
                {
                    if ( (!portA or portA == server_port ) and (!portB or portB == client_port) )
                        return true;
                    else
                        return false;
                }
                else if ( is_ip_match(client_ip, ipA, ipA_subnet) and is_ip_match(server_ip, ipB, ipB_subnet) )
                {
                    if ( (!portA or portA == client_port ) and (!portB or portB == server_port) )
                        return true;
                    else
                        return false;
                }
                else
                    return false;
            }
            else if ( is_ip_match(server_ip, ipA, ipA_subnet) and (!portA or portA == server_port) )
                return true;
            else if ( is_ip_match(client_ip, ipA, ipA_subnet) and (!portA or portA == client_port) )
                return true;
            else
                return false;
        }
        else if ( portA )
        {
            if ( portB )
            {
                if ( (portA == server_port and portB == client_port) or (portA == client_port and portB == server_port) )
                    return true;
                else
                    return false;
            }
            else if ( portA == server_port or portA == client_port )
                return true;
            else
                return false;
        }

        return true;
    }
};
// Wire format for binary flow dumps. This struct is serialized as a raw
// byte image, so its layout is an external contract: any change to field
// order, type, or size alters the on-wire format that downstream consumers
// parse. Keep this struct stable; add console-only fields to the text
// descriptor instead.
struct DumpFlowsBinaryDescriptor
{
    uint32_t flow_id = 0;
    snort::SfIp client_ip;
    snort::SfIp server_ip;
    uint16_t client_port = 0;
    uint16_t server_port = 0;
    uint8_t pkt_type = static_cast<uint8_t>(PktType::NONE);
    unsigned instance_number = 0;
    uint32_t address_space_id = 0;
    uint8_t tcp_client_state = 0;
    uint8_t tcp_server_state = 0;
    uint64_t client_pkts = 0;
    uint64_t server_pkts = 0;
    uint64_t client_bytes = 0;
    uint64_t server_bytes = 0;
    uint64_t expiration_time = 0;
    long idle_time = 0;
    long up_time = 0;
    int remaining_time = 0;
    bool allowed_on_excess = false;
    bool in_allowlist = false;
    uint64_t flow_mem = 0;       // Flow::get_mem_usage() at dump time
    uint64_t peak_flow_mem = 0;  // Flow::get_peak_mem_usage() for the current logical session
};

// Size is ABI-dependent: 144 bytes on 64-bit, 136 on 32-bit ABIs that align
// uint64_t to 8 (ARM, MIPS, PPC) and 132 on those that align it to 4 (i386).
// This assert is a tripwire so a layout change can't slip through unnoticed.
static_assert(sizeof(DumpFlowsBinaryDescriptor) ==
    (sizeof(void*) == 8 ? 144 : (alignof(uint64_t) == 8 ? 136 : 132)),
    "binary flow record format may have changed; ensure all consumers are updated");

class DumpFlowsDescriptor
{
public:
    DumpFlowsDescriptor() = default;
    ~DumpFlowsDescriptor() = default;

    DumpFlowsBinaryDescriptor bin;

    void print(std::fstream& text_stream) const
    {
        char sip[INET6_ADDRSTRLEN];
        sip[0] = 0;
        char dip[INET6_ADDRSTRLEN];
        dip[0] = 0;

        if ( !inet_ntop(bin.client_ip.get_family(),  bin.client_ip.get_ptr(), sip, sizeof(sip)) )
        {
            text_stream << "inet_ntop on src ip failed: " <<  strerror(errno) << " - errno: " << errno << std::endl;
            return;
        }

        if ( !inet_ntop(bin.server_ip.get_family(),  bin.server_ip.get_ptr(), dip, sizeof(dip)) )
        {
           text_stream << "inet_ntop on dst ip failed: " <<  strerror(errno) << " - errno: " << errno << std::endl;
            return;
        }

        std::stringstream proto;
        std::stringstream out;

        out << "Flow ID: " << bin.flow_id << " ";
        switch ( static_cast<PktType>(bin.pkt_type) )
        {
            case PktType::IP:
                out << "Instance-ID: " << bin.instance_number << " IP " << bin.address_space_id << ": " << sip << " " << dip;
                break;

            case PktType::ICMP:
                out << "Instance-ID: " << bin.instance_number << " ICMP " << bin.address_space_id << ": " << sip
                    << " type " << bin.client_port << " " << dip;
                break;

            case PktType::TCP:
                out << "Instance-ID: " << bin.instance_number << " TCP " << bin.address_space_id << ": " << sip
                    << "/" << bin.client_port << " " << dip << "/" << bin.server_port;

                proto << " state client " << stream_tcp_state_to_str(bin.tcp_client_state)
                    << " server " << stream_tcp_state_to_str(bin.tcp_server_state);

                break;

            case PktType::UDP:
                out << "Instance-ID: " << bin.instance_number << " UDP " << bin.address_space_id << ": " << sip << "/" << bin.client_port << " "
                    << dip << "/" << bin.server_port;
                break;

            default:
                assert(false);
        }

        std::string display_str = ( bin.remaining_time < 0 ) ?  "s, timed out for " : "s, timeout in ";
        out << " pkts/bytes client " << bin.client_pkts << "/" << bin.client_bytes
            << " server " << bin.server_pkts << "/" << bin.server_bytes
            << " idle " << bin.idle_time << "s, uptime " << bin.up_time << display_str;
        std::string t = timeout_to_str(bin.expiration_time);
        out << t;

        std::string allow_s;
        if ( bin.allowed_on_excess )
            allow_s = " (allowlist on excess)";
        else if ( bin.in_allowlist )
            allow_s = " (allowlist)";

        out << " flow_mem " << bin.flow_mem << " bytes";
        text_stream << out.str() << proto.str() << allow_s << std::endl;
    }   
};

#endif
