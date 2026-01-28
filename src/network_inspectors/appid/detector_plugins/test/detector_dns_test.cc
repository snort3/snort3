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

// detector_dns_test.cc author Shibin k v <shikv@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_inspector.h"
#include "appid_session.h"
#include "detector_plugins_mock.h"

#include "../detector_dns.h"
#include "../detector_dns.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

Flow::~Flow() = default;
class QuicStreamIntf: public snort::StreamFlowIntf
{
public:
    void get_stream_id(const snort::Flow* flow, int64_t& stream_id) override
    {
        stream_id = 0;
    }
    AppId get_appid_from_stream(const Flow*) override
    {
        return APP_ID_QUIC;
    }
};
static QuicStreamIntf quic_stream_intf;

static ServiceDiscovery test_discovery;

static AppIdDnsSession static_dns_session;

AppIdDnsSession* AppIdSession::get_dns_session() const
{
    return &static_dns_session;
}

AppIdDnsSession* AppIdSession::create_dns_session()
{
    return &static_dns_session;
}

int ServiceDetector::incompatible_data(AppIdSession&, const snort::Packet*, AppidSessionDirection)
{
    return 0;
}
// Stubs for AppIdInspector
static ServiceDNSData dns_data;
static bool return_null_data = false;
ServiceDNSDoQData* dns_doq_data  = nullptr;
AppIdConfig test_app_config;

AppIdInspector::AppIdInspector(AppIdModule&) : config(&test_app_config), ctxt(test_app_config) { }

void AppIdDetector::add_user(AppIdSession&, const char*, AppId, bool, AppidChangeBits&){}

int AppIdDetector::data_add(AppIdSession&, AppIdFlowData* dns_data)
{
    if (return_null_data)
    {
         dns_doq_data = static_cast<ServiceDNSDoQData*>(dns_data);
         return 1;
    }
    return 1;
}

AppIdFlowData* AppIdDetector::data_get(const AppIdSession&)
{
    return return_null_data ? nullptr : &dns_data;
}

int ServiceDetector::fail_service(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir)
{
    return 1;
}

TEST_GROUP(detector_dns_doq_tests)
{
    DnsTcpServiceDetector* const test_detector = nullptr;
    void setup() override
    {
        const_cast<DnsTcpServiceDetector*&>(test_detector) = new DnsTcpServiceDetector(&test_discovery);
    }

    void teardown() override
    {   
        delete test_detector;
        const_cast<DnsTcpServiceDetector*&>(test_detector) = nullptr;
        dns_data.free_dns_cache();
    }
};

TEST(detector_dns_doq_tests, doq_validator_match_full_session)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    dns_data.state = DNS_STATE_QUERY;
    AppIdSession test_asd(IpProtocol::TCP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    Flow* flow = new Flow;
    test_asd.flow = flow;
    uint8_t dns_tcp_packet[] = {
        0x00, 0x1c, // TCP length (28 bytes)
        0x12, 0x34, // id
        0x01, 0x00, // flags
        0x00, 0x01, // QDCount
        0x00, 0x00, // ANCount
        0x00, 0x00, // NSCount
        0x00, 0x00, // ARCount
        0x03, 'w', 'w', 'w', 0x00, // "www"
        0x00, 0x01, // QType A
        0x00, 0x01  // QClass IN
    };

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(dns_tcp_packet, sizeof(dns_tcp_packet), APP_ID_FROM_INITIATOR, test_asd, nullptr, change_bits);
    auto result = test_detector->validate_doq(args);
    dns_data.free_dns_cache();
    CHECK_EQUAL(APPID_INPROCESS, result);

    // Now send a response packet
    dns_data.state = DNS_STATE_RESPONSE;
    dns_data.id = 13330;
    uint8_t dns_tcp_response[] = {
        0x00, 0x25,             // TCP length (37 bytes)
        0x12, 0x34,             // id
        0x81, 0x80,             // flags: standard response, no error
        0x00, 0x01,             // QDCount: 1
        0x00, 0x01,             // ANCount: 1
        0x00, 0x00,             // NSCount: 0
        0x00, 0x00,             // ARCount: 0
        // Query: www
        0x03, 'w', 'w', 'w', 0x00, // QNAME: "www"
        0x00, 0x01,             // QType: A
        0x00, 0x01,             // QClass: IN
        // Answer
        0xc0, 0x0c,             // Name (pointer to offset 12)
        0x00, 0x01,             // Type: A
        0x00, 0x01,             // Class: IN
        0x00, 0x00, 0x00, 0x3c, // TTL: 60
        0x00, 0x04,             // RDLENGTH: 4
        0x7f, 0x00, 0x00, 0x01  // RDATA: 127.0.0.1
    };

    AppIdDiscoveryArgs response_args(dns_tcp_response, sizeof(dns_tcp_response), APP_ID_FROM_RESPONDER, test_asd, nullptr, change_bits);
    result = test_detector->validate_doq(response_args);
    delete flow;
    CHECK_EQUAL(APPID_SUCCESS, result);
}

TEST(detector_dns_doq_tests, doq_validator_in_process_cached)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    dns_data.state = DNS_STATE_QUERY;
    AppIdSession test_asd(IpProtocol::TCP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    Flow* flow = new Flow;
    test_asd.flow = flow;
    // partial data
    uint8_t dns_tcp_packet_1[] = {
        0x00, 0x1c, // TCP length (28 bytes)
        0x12, 0x34, // id
        0x01, 0x00, // flags
    };

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(dns_tcp_packet_1, sizeof(dns_tcp_packet_1), APP_ID_FROM_INITIATOR, test_asd, nullptr, change_bits);
    auto result = test_detector->validate_doq(args);
    CHECK_EQUAL(6, dns_data.cached_len);
    CHECK_EQUAL(APPID_INPROCESS, result);

    uint8_t dns_tcp_packet_2[]= {
        0x00, 0x01, // QDCount
        0x00, 0x00, // ANCount
        0x00, 0x00, // NSCount
        0x00, 0x00, // ARCount
        0x03, 'w', 'w', 'w', 0x00, // "www"
        0x00, 0x01, // QType A
        0x00, 0x01  // QClass IN
    };
    AppIdDiscoveryArgs args2(dns_tcp_packet_2, sizeof(dns_tcp_packet_2), APP_ID_FROM_INITIATOR, test_asd, nullptr, change_bits);
    result = test_detector->validate_doq(args2);
    delete flow;
    CHECK_EQUAL(APPID_INPROCESS, result);
}

TEST(detector_dns_doq_tests, doq_validator_not_compatible)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    dns_data.state = DNS_STATE_QUERY;
    AppIdSession test_asd(IpProtocol::TCP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    Flow* flow = new Flow;
    test_asd.flow = flow;

    uint8_t dns_tcp_packet[] = {
        0x00, 0x01, // TCP length (1 bytes)
        0x12, 0x34, // id
        0x01, 0x00, // flags
        0x00, 0x01, // QDCount
        0x00, 0x00, // ANCount
        0x00, 0x00, // NSCount
        0x00, 0x00, // ARCount
        0x03, 'w', 'w', 'w', 0x00, // "www"
        0x00, 0x01, // QType A
        0x00, 0x01  // QClass IN
    };

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(dns_tcp_packet, sizeof(dns_tcp_packet), APP_ID_FROM_INITIATOR, test_asd, nullptr, change_bits);
    auto result = test_detector->validate_doq(args);
    delete flow;
    CHECK_EQUAL(APPID_NOT_COMPATIBLE, result);

}

TEST(detector_dns_doq_tests, doq_validator_no_match)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    dns_data.state = DNS_STATE_QUERY;
    AppIdSession test_asd(IpProtocol::TCP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    Flow* flow = new Flow;
    test_asd.flow = flow;
    uint8_t dns_tcp_packet[] = {
        0x00, 0x10, // TCP length (28 bytes)
        0x12, 0x34, // id
        0x01, 0x00, // flags
        0x00, 0x01, // QDCount
        0x00, 0x00, // ANCount
        0x00, 0x00, // NSCount
        0x00, 0x00, // ARCount
        0x03, 'w', 'w', 'w', 0x00, // "www"
        0x00, 0x01, // QType A
        0x00, 0x01  // QClass IN
    };

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(dns_tcp_packet, sizeof(dns_tcp_packet), APP_ID_FROM_RESPONDER, test_asd, nullptr, change_bits);
    auto result = test_detector->validate_doq(args);
    delete flow;
    CHECK_EQUAL(APPID_NOMATCH, result);
}

TEST(detector_dns_doq_tests, doq_validator_stream_intf)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    dns_data.state = DNS_STATE_QUERY;
    AppIdSession test_asd(IpProtocol::TCP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    Flow* flow = new Flow;
    test_asd.flow = flow;
    flow->stream_intf = &quic_stream_intf;
    return_null_data = true; // Set flag to return nullptr from data_get
    uint8_t dns_tcp_packet[] = {
        0x00, 0x1c, // TCP length (28 bytes)
        0x12, 0x34, // id
        0x01, 0x00, // flags
        0x00, 0x01, // QDCount
        0x00, 0x00, // ANCount
        0x00, 0x00, // NSCount
        0x00, 0x00, // ARCount
        0x03, 'w', 'w', 'w', 0x00, // "www"
        0x00, 0x01, // QType A
        0x00, 0x01  // QClass IN
    };

    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(dns_tcp_packet, sizeof(dns_tcp_packet), APP_ID_FROM_INITIATOR, test_asd, nullptr, change_bits);
    auto result = test_detector->validate_doq(args);
    delete flow;
    return_null_data = false;
    delete dns_doq_data;
    dns_doq_data = nullptr;
    CHECK_EQUAL(APPID_INPROCESS, result);
}



int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
