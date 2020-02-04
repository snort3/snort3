//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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

// cisco_meta_data_test.cc author Sunirmal Mukherjee <sunimukh@cisco.com> 
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "protocols/cisco_meta_data.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// tests
//-------------------------------------------------------------------------

Packet::Packet(bool) { }
Packet::~Packet()  = default;

namespace snort
{
void ip::IpApi::set(ip::IP4Hdr const* iph)
{
    return;
}

void ip::IpApi::set(ip::IP6Hdr const* iph)
{
    return;
}

void ip::IpApi::reset()
{
    return;
}

const uint8_t* ip::IpApi::ip_data() const
{
    return nullptr;
}
}

static inline void push_layer(Packet* p,
    ProtocolId prot_id,
    const uint8_t* hdr_start,
    uint32_t len)
{
    Layer& lyr = p->layers[p->num_layers++];
    lyr.prot_id = prot_id;
    lyr.start = hdr_start;
    lyr.length = (uint16_t)len;
}
    
TEST_GROUP(cisco_meta_data_test)
{
};

TEST(cisco_meta_data_test, cisco_meta_data_class_test)
{
    Packet pkt(false);
    Layer layers;
    uint8_t * cmd_data;
    int len;
    int sgt;
    
    pkt.num_layers = 0;
    pkt.layers = &layers;

    cmd_data = new uint8_t[sizeof(cisco_meta_data::CiscoMetaDataHdr) + sizeof(cisco_meta_data::CiscoMetaDataOpt)];

    cisco_meta_data::CiscoMetaDataOpt* cmd_options =
        reinterpret_cast<cisco_meta_data::CiscoMetaDataOpt*>(cmd_data + sizeof(cisco_meta_data::CiscoMetaDataHdr)); 
    cmd_options->sgt = 512;

    len = (sizeof(cisco_meta_data::CiscoMetaDataHdr) + sizeof(cisco_meta_data::CiscoMetaDataOpt));
    pkt.proto_bits |= PROTO_BIT__CISCO_META_DATA;
    push_layer(&pkt, ProtocolId::ETHERTYPE_CISCO_META, cmd_data, len);
    sgt = htons(layer::get_cisco_meta_data_layer(&pkt)->sgt_val());
    CHECK(sgt == cmd_options->sgt);

    delete[] cmd_data;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

