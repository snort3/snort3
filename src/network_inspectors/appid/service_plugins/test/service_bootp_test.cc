//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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
//
// service_bootp_test.cc author Bohdan Hryniv <bhryniv@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../service_bootp.h"
#include "../service_bootp.cc"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
namespace layer
{
static eth::EtherHdr s_mock_eth_hdr = {};
static const eth::EtherHdr* s_mock_eth_hdr_ptr = &s_mock_eth_hdr;
const eth::EtherHdr* get_eth_layer(const Packet*) { return s_mock_eth_hdr_ptr; }
}
}

AppIdModule::AppIdModule() : Module("a", "b") { }
AppIdModule::~AppIdModule() = default;

static AppIdConfig test_config;
static ServiceDiscovery mock_sd;
static BootpServiceDetector detector(&mock_sd);
static snort::Packet mock_pkt(false);
static snort::SfIp mock_ip;
static AppIdModule mock_module;

AppIdInspector::AppIdInspector(AppIdModule&) : config(&test_config), ctxt(test_config) { }

static AppIdInspector test_inspector(mock_module);
static OdpContext test_odp(test_config, nullptr);
static AppIdSession test_asd(IpProtocol::UDP, &mock_ip, 67, test_inspector, test_odp, 0, 0);

static void build_bootp_header(uint8_t* buf, uint8_t op)
{
    memset(buf, 0, sizeof(ServiceBOOTPHeader));
    ServiceBOOTPHeader* bh = reinterpret_cast<ServiceBOOTPHeader*>(buf);
    bh->op = op;
    bh->htype = 0x01;
    bh->hlen = 0x06;
}

static void add_magic_cookie(uint8_t* buf)
{
    buf[0] = 0x63;
    buf[1] = 0x82;
    buf[2] = 0x53;
    buf[3] = 0x63;
}

TEST_GROUP(bootp_parsing_tests)
{
    void setup() override
    {
    }
    void teardown() override
    {
    }
};

TEST(bootp_parsing_tests, dhcp_request_truncated_option_header)
{
    uint8_t pkt[sizeof(ServiceBOOTPHeader) + 4 + 1];
    build_bootp_header(pkt, 0x01);
    add_magic_cookie(pkt + sizeof(ServiceBOOTPHeader));
    pkt[sizeof(ServiceBOOTPHeader) + 4] = 0x35;

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_INITIATOR,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOT_COMPATIBLE, ret);
}

TEST(bootp_parsing_tests, dhcp_reply_truncated_option_header)
{
    uint8_t pkt[sizeof(ServiceBOOTPHeader) + 4 + 1];
    build_bootp_header(pkt, 0x02);
    add_magic_cookie(pkt + sizeof(ServiceBOOTPHeader));
    pkt[sizeof(ServiceBOOTPHeader) + 4] = 0x35;

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
}

TEST(bootp_parsing_tests, dhcp_reply_multi_option_then_truncated)
{
    uint8_t pkt[sizeof(ServiceBOOTPHeader) + 4 + 4];
    build_bootp_header(pkt, 0x02);
    add_magic_cookie(pkt + sizeof(ServiceBOOTPHeader));
    pkt[sizeof(ServiceBOOTPHeader) + 4] = 53;
    pkt[sizeof(ServiceBOOTPHeader) + 5] = 1;
    pkt[sizeof(ServiceBOOTPHeader) + 6] = 5;
    pkt[sizeof(ServiceBOOTPHeader) + 7] = 0x01;

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
