//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// geneve_codec_test.cc author Steve Chew <stechew@cisco.com>

#include "../cd_geneve.cc"

#include "utils/endian.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

namespace snort
{
    bool TextLog_Print(TextLog* const, const char*, ...) { return false; }
    void Codec::codec_event(const CodecData&, CodecSid) { }
    bool SnortConfig::tunnel_bypass_enabled(unsigned short) const { return false; }
}

// Geneve data with 2 variable options.
uint8_t geneve_pkt_data[] = {
0x05,                       // version and option length in 4-byte chunks
0x00,                       // flags
0x65,0x58,                  // protocol type
0x00,0x00,0x01,             // VNI
0x00,                       // reserved
0x01, 0x06,                 // Cisco variable option class
0x56,                       // Variable option type
0x02,                       // Variable option data length in 4-byte chunks
0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x40,    // Variable option data
0x01,0x06,                  // Cisco variable option class
0x02,                       // Variable option type
0x01,                       // Variable option data length in 4-byte chunks
0xac,0x10,0xa0,0x02         // Variable option data
};

// Geneve data with 0 variable options.
uint8_t geneve_pkt_data_no_options[] = {
0x00,                       // version and option length in 4-byte chunks
0x00,                       // flags
0x65,0x58,                  // protocol type
0x00,0x00,0x01,             // VNI
0x00,                       // reserved
};


// A sample function to convert the option data to uint64_t.
bool get_geneve_opt_data(std::vector<snort::geneve::GeneveOptData> options, uint16_t g_class, uint8_t g_type, uint64_t& value)
{
    value = 0;

    for (const auto& opt_data : options)
    {
        if (opt_data.opt.optclass() == g_class and opt_data.opt.type() == g_type)
        {
            uint8_t data_len = opt_data.opt.data_len();
            if (data_len == 4)
                value = ntohl(*(uint32_t*)opt_data.data);
            else if (data_len == 8)
                value = ntohll(*(uint64_t*)opt_data.data);
            else
                return false;

            return true;
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Geneve codec tests
//--------------------------------------------------------------------------

TEST_GROUP(geneve_codec_tests)
{
};

TEST(geneve_codec_tests, decode)
{
    GeneveCodec geneve_codec;
    RawData raw_data(nullptr, geneve_pkt_data, sizeof(geneve_pkt_data));
    CodecData codec_data(nullptr, ProtocolId::GENEVE);
    DecodeData decode_data;

    CHECK_TRUE( geneve_codec.decode(raw_data, codec_data, decode_data) );
    CHECK(codec_data.lyr_len == sizeof(geneve_pkt_data));
    CHECK(codec_data.proto_bits == PROTO_BIT__GENEVE);
    CHECK(codec_data.next_prot_id == ProtocolId::ETHERNET_802_3);
    CHECK(codec_data.codec_flags == CODEC_NON_IP_TUNNEL);
}

TEST(geneve_codec_tests, geneve_lyr)
{
    geneve::GeneveLyr* glyr = (geneve::GeneveLyr*)geneve_pkt_data;

    std::vector<geneve::GeneveOptData> opt_data = glyr->get_opt_data();

    CHECK( opt_data.size() == 2 );

    CHECK( opt_data[0].opt.olen() == 12 );
    CHECK( opt_data[0].opt.data_len() == 8 );
    CHECK( opt_data[0].opt.optclass() == 0x0106 );
    CHECK( opt_data[0].opt.type() == 0x56 );

    uint8_t opt0_data[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x40};
    CHECK( memcmp(opt_data[0].data, opt0_data, opt_data[0].opt.data_len()) == 0);

    CHECK( opt_data[1].opt.olen() == 8 );
    CHECK( opt_data[1].opt.data_len() == 4 );
    CHECK( opt_data[1].opt.optclass() == 0x0106 );
    CHECK( opt_data[1].opt.type() == 0x02 );

    uint8_t opt1_data[] = {0xac,0x10,0xa0,0x02};
    CHECK( memcmp(opt_data[1].data, opt1_data, opt_data[1].opt.data_len()) == 0);

    uint64_t value = 0;
    CHECK( get_geneve_opt_data(opt_data, 0x0106, 0x56, value) );
    CHECK( value == 2112 );
}

TEST(geneve_codec_tests, geneve_lyr_no_options)
{
    geneve::GeneveLyr* glyr = (geneve::GeneveLyr*)geneve_pkt_data_no_options;
    std::vector<geneve::GeneveOptData> opt_data = glyr->get_opt_data();
    CHECK( opt_data.empty() );
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

