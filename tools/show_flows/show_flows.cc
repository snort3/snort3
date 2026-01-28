//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// show_flows.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include "errno.h"
#include <getopt.h>
#include <netinet/in.h>

#include "flow/dump_flows_descriptor.h"
#include "framework/decode_data.h"

#include "sfip/sf_ip.h"

using namespace snort;

// duplicate of structure in stream_module.h    
static const std::map<std::string, PktType> protocol_to_type =
{
    {"TCP", PktType::TCP},
    {"UDP", PktType::UDP},
    {"IP", PktType::IP},
    {"ICMP", PktType::ICMP},
};

const struct option longopts[] =
  {
    {"version",   no_argument,        0, 'v'},
    {"help",      no_argument,        0, 'h'},
    {"file",      required_argument,  0, 'f'},
    {"protocol",  required_argument,  0, 'p'},
    {"srcip",     required_argument,  0, 'r'},
    {"dstip",     required_argument,  0, 't'},
    {"srcport",   required_argument,  0, 's'},
    {"dstport",   required_argument,  0, 'd'},
    {0,0,0,0},
  };

class DumpFlowsFilterAllAnd : public DumpFlowsFilter
{
public:

    DumpFlowsFilterAllAnd(bool enable_binary_output)
        : DumpFlowsFilter(enable_binary_output)
    { }

    virtual ~DumpFlowsFilterAllAnd() override
    { }

    bool filter_flow(const snort::SfIp& server_ip, const snort::SfIp& client_ip, 
        uint16_t server_port, uint16_t client_port, PktType flow_pkt_type ) override
    {
        if ( proto_type != PktType::NONE and proto_type != flow_pkt_type )
            return false;

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

class DumpFlowsDeSerializer
{
public:
    DumpFlowsDeSerializer(DumpFlowsFilter& dff)
    : dff(dff)
    { }

    ~DumpFlowsDeSerializer() {}

    void deserialize(std::fstream& bin_stream, std::fstream& text_stream);

private:
    DumpFlowsDescriptor dfd;
    DumpFlowsFilter& dff;
};

void DumpFlowsDeSerializer::deserialize(std::fstream& bin_stream, std::fstream& text_stream)
{
    if ( dff.filter_none )
    {
        while ( bin_stream.read(reinterpret_cast<char*>(&dfd), sizeof(DumpFlowsDescriptor)) )
            dfd.print(text_stream);
    }
    else
    {
        while ( bin_stream.read(reinterpret_cast<char*>(&dfd), sizeof(DumpFlowsDescriptor)) )
            if ( dff.filter_flow(dfd.client_ip, dfd.server_ip, dfd.client_port, dfd.server_port, (PktType) dfd.pkt_type) )
                dfd.print(text_stream);
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <name>" << std::endl;
        return 1; // Indicate an error
    }

    std::string file_name;
    DumpFlowsFilterAnd dff(false);

    int iarg = 0;
    int index = 0;

    while( iarg != -1 )
    {
        iarg = getopt_long(argc, argv, "vhf:p:r:t:s:d:", longopts, &index);

        switch (iarg)
        {
        case 'f':
            file_name = optarg;
            break;

        case 'h':
            std::cout << "Usage:" << std::endl;
            std::cout << "\tshow_flows -h - print this help" << std::endl;
            std::cout << "\tshow_flows -v - print the version" << std::endl;
            std::cout << "\tshow_flows -f <filename> -r <src ip> -t <dst ip> -s <src port> -d <dst port> -p <protocol>" << std::endl;
            exit(0);
            break;

        case 'v':
            std::cout << "show_flows - version 0.01" << std::endl;
            exit(0);
            break;

        case 'r':
        {  
            std::string srcip(optarg);
            if ( !dff.set_ipA(srcip) )
            {
                std::cerr << "inet_pton on src ip failed: " <<  strerror(errno) << " - errno: " << errno << std::endl; 
                exit(1);
            }
            
            dff.filter_none = false;
            break;
        }

        case 't':
        {
            std::string dstip(optarg);
            if ( !dff.set_ipB(dstip) )
            {
                std::cerr << "inet_pton on dest ip failed: " <<  strerror(errno) << " - errno: " << errno << std::endl; 
                exit(1);
            }

            dff.filter_none = false;
            break;
        }

        case 'd':
            dff.portB = atoi(optarg);
            dff.filter_none = false;
            break;

        case 's':
            dff.portA = atoi(optarg);
            dff.filter_none = false;
            break;

        case 'p':
            if ( optarg[0] != '\0' )
            {
                auto proto_it = protocol_to_type.find(optarg);
                if ( proto_it == protocol_to_type.end() )
                {
                    std::cerr << "Invalid Protocol; valid protocols are IP/TCP/UDP/ICMP" << std::endl;
                    exit(1);
                }
                else
                    dff.proto_type = proto_it->second;    
            }

            dff.filter_none = false;
            break;
        }
  }

    if ( file_name.empty() )
    {
        std::cerr << "Input file name must be specified" << std::endl;
        exit(1);
    }

    std::string binary_file_name = file_name + ".bin";

    std::fstream df_bin_stream;
    df_bin_stream.open(binary_file_name, std::ios::binary | std::ios::in);
    if ( df_bin_stream.rdstate() & std::fstream::failbit )
    {
        std::cerr << "show_flows failed to open binary file: " << binary_file_name << std::endl;
        exit(1);
    }

    std::fstream df_text_stream;
    df_text_stream.open(file_name, std::ios::out | std::ios::trunc);
    if ( df_text_stream.rdstate() & std::fstream::failbit )
    {
        std::cerr << "show_flows failed to open text file: " << file_name << std::endl;
        exit(1);
    }

    DumpFlowsDeSerializer dfd(dff);
    dfd.deserialize(df_bin_stream, df_text_stream);

    exit(0);
}

SfIpRet SfIp::set(const void* src, int fam)
{
    assert(src);

    family = fam;
    if (family == AF_INET)
    {
        ip32[0] = ip32[1] = ip16[4] = 0;
        ip16[5] = 0xffff;
        ip32[3] = *(const uint32_t*)src;
    }
    else if (family == AF_INET6)
        memcpy(ip8, src, 16);
    else
        return SFIP_ARG_ERR;

    return SFIP_SUCCESS;
}

/* Converts string IP format to an array of values. Also checks IP address format.
   Specifically look for issues that inet_pton either overlooks or is inconsistent
   about.  */
SfIpRet snort::SfIp::pton(const int fam, const char* ip)
{
    const char* my_ip = ip;
    void* dst;

    if (!my_ip)
        return SFIP_FAILURE;

    /* Across platforms, inet_pton() is inconsistent about leading 0's in
       AF_INET (ie IPv4 addresses). */
    if (fam == AF_INET)
    {
        char chr;
        bool new_octet;

        new_octet = true;
        while ((chr = *my_ip++) != '\0')
        {
            /* If we are at the first char of a new octet, look for a leading zero
               followed by another digit */
            if (new_octet && (chr == '0') && isdigit(*my_ip))
                return SFIP_INET_PARSE_ERR;

            /* when we see an octet separator, set the flag to start looking for a
               leading zero. */
            new_octet = (chr == '.');
        }
        ip32[0] = ip32[1] = ip16[4] = 0;
        ip16[5] = 0xffff;
        dst = &ip32[3];
    }
    else
        dst = ip32;

    if (inet_pton(fam, ip, dst) < 1)
        return SFIP_INET_PARSE_ERR;

    family = fam;

    return SFIP_SUCCESS;  /* Otherwise, ip is OK */
}
