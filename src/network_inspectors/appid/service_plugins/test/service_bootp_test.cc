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

TEST_GROUP(dhcp_option_overload_helper_tests) { };

TEST(dhcp_option_overload_helper_tests, parse_option_area_router_extracted)
{
    uint8_t area[] = { 0x03, 0x04, 0x0A, 0x64, 0x01, 0x02, 0xFF };
    int option53 = 0;
    uint32_t subnet = 0, router = 0, leaseTime = 0;

    bool result = parse_dhcp_options_area(area, sizeof(area), option53, subnet, router, leaseTime);

    CHECK_EQUAL(true, result);
    uint32_t expected_router;
    uint8_t ip[] = { 0x0A, 0x64, 0x01, 0x02 };
    memcpy(&expected_router, ip, 4);
    CHECK_EQUAL(expected_router, router);
    CHECK_EQUAL(0, option53);
    CHECK_EQUAL(0u, subnet);
    CHECK_EQUAL(0u, leaseTime);
}

TEST(dhcp_option_overload_helper_tests, parse_option_area_dhcpack_type_extracted)
{
    uint8_t area[] = { 0x35, 0x01, 0x05, 0xFF };
    int option53 = 0;
    uint32_t subnet = 0, router = 0, leaseTime = 0;

    bool result = parse_dhcp_options_area(area, sizeof(area), option53, subnet, router, leaseTime);

    CHECK_EQUAL(true, result);
    CHECK_EQUAL(1, option53);
}

TEST(dhcp_option_overload_helper_tests, parse_option_area_pad_bytes_skipped)
{
    uint8_t area[] = { 0x00, 0x00, 0x03, 0x04, 0xC0, 0xA8, 0x01, 0x01, 0xFF };
    int option53 = 0;
    uint32_t subnet = 0, router = 0, leaseTime = 0;

    bool result = parse_dhcp_options_area(area, sizeof(area), option53, subnet, router, leaseTime);

    CHECK_EQUAL(true, result);
    uint32_t expected_router;
    uint8_t ip[] = { 0xC0, 0xA8, 0x01, 0x01 };
    memcpy(&expected_router, ip, 4);
    CHECK_EQUAL(expected_router, router);
}

TEST(dhcp_option_overload_helper_tests, parse_option_area_truncated_returns_false)
{
    uint8_t area[] = { 0x03 };
    int option53 = 0;
    uint32_t subnet = 0, router = 0, leaseTime = 0;

    bool result = parse_dhcp_options_area(area, sizeof(area), option53, subnet, router, leaseTime);

    CHECK_EQUAL(false, result);
}

TEST(dhcp_option_overload_helper_tests, parse_option_area_truncated_value_returns_false)
{
    uint8_t area[] = { 0x03, 0x04, 0xC0, 0xA8 };
    int option53 = 0;
    uint32_t subnet = 0, router = 0, leaseTime = 0;

    bool result = parse_dhcp_options_area(area, sizeof(area), option53, subnet, router, leaseTime);

    CHECK_EQUAL(false, result);
}

TEST(dhcp_option_overload_helper_tests, parse_option_area_no_end_marker)
{
    uint8_t area[] = { 0x03, 0x04, 0xC0, 0xA8, 0x01, 0x01 };
    int option53 = 0;
    uint32_t subnet = 0, router = 0, leaseTime = 0;

    bool result = parse_dhcp_options_area(area, sizeof(area), option53, subnet, router, leaseTime);

    CHECK_EQUAL(false, result);
}

TEST_GROUP(dhcp_overload_packet_tests) { };

TEST(dhcp_overload_packet_tests, dhcp_reply_option52_sname_overloaded_accepted)
{
    uint8_t std_opts[] = {
        0x35, 0x01, 0x05,
        0x34, 0x01, 0x02,
        0xFF
    };

    uint8_t pkt[sizeof(ServiceBOOTPHeader) + 4 + sizeof(std_opts)];
    build_bootp_header(pkt, 0x02);

    ServiceBOOTPHeader* bh = reinterpret_cast<ServiceBOOTPHeader*>(pkt);
    bh->sname[0] = 0x03;
    bh->sname[1] = 0x04;
    bh->sname[2] = 0x0A;  
    bh->sname[3] = 0x64;
    bh->sname[4] = 0x01;  
    bh->sname[5] = 0x02;
    bh->sname[6] = 0xFF;

    add_magic_cookie(pkt + sizeof(ServiceBOOTPHeader));
    memcpy(pkt + sizeof(ServiceBOOTPHeader) + 4, std_opts, sizeof(std_opts));

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_SUCCESS, ret);
}

TEST(dhcp_overload_packet_tests, dhcp_reply_option52_file_overloaded_accepted)
{
    uint8_t std_opts[] = {
        0x35, 0x01, 0x05,
        0x34, 0x01, 0x01,
        0xFF
    };

    uint8_t pkt[sizeof(ServiceBOOTPHeader) + 4 + sizeof(std_opts)];
    build_bootp_header(pkt, 0x02);

    ServiceBOOTPHeader* bh = reinterpret_cast<ServiceBOOTPHeader*>(pkt);
    bh->file[0] = 0x03;
    bh->file[1] = 0x04;
    bh->file[2] = 0x0A;  bh->file[3] = 0x64;
    bh->file[4] = 0x01;  bh->file[5] = 0x03;
    bh->file[6] = 0xFF;

    add_magic_cookie(pkt + sizeof(ServiceBOOTPHeader));
    memcpy(pkt + sizeof(ServiceBOOTPHeader) + 4, std_opts, sizeof(std_opts));

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_SUCCESS, ret);
}

TEST(dhcp_overload_packet_tests, dhcp_reply_option52_both_overloaded_accepted)
{
    uint8_t std_opts[] = {
        0x35, 0x01, 0x05,
        0x34, 0x01, 0x03,
        0xFF
    };

    uint8_t pkt[sizeof(ServiceBOOTPHeader) + 4 + sizeof(std_opts)];
    build_bootp_header(pkt, 0x02);

    ServiceBOOTPHeader* bh = reinterpret_cast<ServiceBOOTPHeader*>(pkt);
    // Router in sname
    bh->sname[0] = 0x03; bh->sname[1] = 0x04;
    bh->sname[2] = 0x0A; bh->sname[3] = 0x64;
    bh->sname[4] = 0x01; bh->sname[5] = 0x02;
    bh->sname[6] = 0xFF;
    // Subnet mask in file
    bh->file[0] = 0x01; bh->file[1] = 0x04;
    bh->file[2] = 0xFF; bh->file[3] = 0xFF;
    bh->file[4] = 0xFF; bh->file[5] = 0x00;
    bh->file[6] = 0xFF;

    add_magic_cookie(pkt + sizeof(ServiceBOOTPHeader));
    memcpy(pkt + sizeof(ServiceBOOTPHeader) + 4, std_opts, sizeof(std_opts));

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_SUCCESS, ret);
}

TEST(dhcp_overload_packet_tests, dhcp_reply_invalid_overload_value_ignored)
{
    uint8_t std_opts[] = {
        0x35, 0x01, 0x05,
        0x34, 0x01, 0x04,
        0xFF
    };

    uint8_t pkt[sizeof(ServiceBOOTPHeader) + 4 + sizeof(std_opts)];
    build_bootp_header(pkt, 0x02);
    add_magic_cookie(pkt + sizeof(ServiceBOOTPHeader));
    memcpy(pkt + sizeof(ServiceBOOTPHeader) + 4, std_opts, sizeof(std_opts));

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_SUCCESS, ret);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
