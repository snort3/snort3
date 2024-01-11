//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

// service_netbios_test.cc author Kani Murthi<kamurthi@cisco.com>
// unit test for service_netbios
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/service_plugins/service_detector.cc"
#include "network_inspectors/appid/service_plugins/service_netbios.cc"
#include "protocols/packet.h"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void ServiceDiscovery::initialize(AppIdInspector&) {}
void ServiceDiscovery::reload() {}
void ServiceDiscovery::finalize_service_patterns() {}
void ServiceDiscovery::match_by_pattern(AppIdSession&, const Packet*, IpProtocol) {}
void ServiceDiscovery::get_port_based_services(IpProtocol, uint16_t, AppIdSession&) {}
void ServiceDiscovery::get_next_service(const Packet*, const AppidSessionDirection, AppIdSession&)
{}
int ServiceDiscovery::identify_service(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return 0; }
int ServiceDiscovery::add_ftp_service_state(AppIdSession&) { return 0; }
bool ServiceDiscovery::do_service_discovery(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return false; }
int ServiceDiscovery::incompatible_data(AppIdSession&, const Packet*,AppidSessionDirection,
    ServiceDetector*) { return 0; }
int ServiceDiscovery::fail_service(AppIdSession&, const Packet*, AppidSessionDirection,
    ServiceDetector*, ServiceDiscoveryState*) { return 0; }
int ServiceDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }
void AppIdSessionApi::set_netbios_name(AppidChangeBits&, const char*) {}
void AppIdSessionApi::set_netbios_domain(AppidChangeBits&, const char*) {}

TEST_GROUP(service_netbios_test){};

TEST(service_netbios_test, check_add_smb_info_pointer )
{
    const uint8_t data[] = { 0x11, 0x02, 0x45, 0x63, 0xac, 0x1f, 0x13, 0x49, 0x00, 0x8a, 0x00, 0xd7,
        0x00, 0x00, 0x20, 0x45, 0x50, 0x45, 0x4c, 0x45, 0x4a, 0x43, 0x4e, 0x44, 0x42, 0x44, 0x46,
        0x45, 0x46, 0x44, 0x47, 0x45, 0x43, 0x45, 0x44, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x41, 0x41, 0x00, 0x20, 0x46, 0x48, 0x45, 0x50, 0x46, 0x43, 0x45, 0x4c,
        0x45, 0x48, 0x46, 0x43, 0x45, 0x50, 0x46, 0x46, 0x46, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x42, 0x4e, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x25,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00,
        0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x56, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x40, 0x00, 0x5c, 0x4d, 0x41, 0x49, 0x4c, 0x53, 0x4c, 0x4f, 0x54, 0x5c, 0x42,
        0x52, 0x4f, 0x57, 0x53, 0x45, 0x00, 0x01, 0x00, 0x60, 0xea, 0x00, 0x00, 0x4f, 0x4b, 0x49,
        0x2d, 0x31, 0x35, 0x45, 0x36, 0x42, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x03, 0x22, 0x41, 0x00, 0x0f, 0x01, 0x55, 0xaa, 0x43, 0x68, 0x61, 0x6e, 0x64, 0x72, 0x61,
        0x27, 0x73, 0x20, 0x63, 0x75, 0x62, 0x65, 0x01};
    uint16_t size =215;
    AppidSessionDirection dir = APP_ID_FROM_INITIATOR;
    AppIdInspector ins;
    OdpContext odp_ctxt(config, nullptr);
    snort::Packet pkt;
    AppidChangeBits cb;
    SfIp ip;
    AppIdSession asd(IpProtocol::TCP, &ip, 21, ins, odp_ctxt);
    AppIdDiscoveryArgs args(data, size, dir, asd, &pkt,cb);
    ServiceDiscovery& s_discovery_manager = asd.get_odp_ctxt().get_service_disco_mgr();
    args.pkt->ptrs.sp = args.pkt->ptrs.dp = 138;
    NbdgmServiceDetector nsd(&s_discovery_manager);
    nsd.validate(args);
    FpSMBData *smb_ptr1 = (FpSMBData*)(asd.get_flow_data(APPID_SESSION_DATA_SMB_DATA));
    nsd.validate(args);
    FpSMBData *smb_ptr2 = (FpSMBData*)(asd.get_flow_data(APPID_SESSION_DATA_SMB_DATA));
    CHECK(smb_ptr1 == smb_ptr2);
    asd.free_flow_data();
    delete &asd.get_api();
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
