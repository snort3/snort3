//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// encap_layer_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>

#include "flow/expect_flow.h"
#include "packet_io/packet_tracer.h"
#include "packet_io/sfdaq_instance.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

// Stubs for undefined symbols
void snort::ExpectFlow::reset_expect_flows() {}

// SfIp stubs
SfIpRet SfIp::set(const void* src, int fam)
{
    if (fam == AF_INET)
        memcpy(&ip8[12], src, 4);
    else if (fam == AF_INET6)
        memcpy(ip8, src, 16);
    family = fam;
    return SFIP_SUCCESS;
}

SfIpRet SfIp::set(const void* src)
{
    memcpy(ip8, src, 16);
    family = AF_INET6;
    return SFIP_SUCCESS;
}

void ip::IpApi::reset() { type = IAT_NONE; }

void ip::IpApi::set(const ip::IP4Hdr* h)
{
    if (h)
    {
        type = IAT_4;
        iph = h;
        src.set(&h->ip_src, AF_INET);
        dst.set(&h->ip_dst, AF_INET);
    }
}

void ip::IpApi::set(const ip::IP6Hdr* h)
{
    if (h)
    {
        type = IAT_6;
        iph = h;
        src.set(h->get_src());
        dst.set(h->get_dst());
    }
}

IpProtocol ip::IpApi::proto() const
{
    if (type == IAT_4)
        return ((const ip::IP4Hdr*)iph)->proto();
    if (type == IAT_6)
        return ((const ip::IP6Hdr*)iph)->next();
    return IpProtocol::PROTO_NOT_SET;
}

const uint8_t* ip::IpApi::ip_data() const { return nullptr; }
const char* PacketManager::get_proto_name(ProtocolId) { return nullptr; }
int SFDAQInstance::inject(_daq_msg const*, int, unsigned char const*, unsigned int) { return -1; }
int SFDAQInstance::ioctl(DAQ_IoctlCmd, void*, size_t) { return DAQ_SUCCESS; }
bool SFDAQInstance::can_invoke_inject_drop() const { return false; }
void PacketTracer::log(const char*, ...) { }
uint8_t PacketManager::max_layers = 255;

TEST_GROUP(encap_layer_tests)
{
};

TEST(encap_layer_tests, get_tunnel_type_name_vxlan)
{
    const char* name = layer::get_tunnel_type_name(ProtocolId::VXLAN);
    STRCMP_EQUAL("vxlan", name);
}

TEST(encap_layer_tests, get_tunnel_type_name_gre)
{
    const char* name = layer::get_tunnel_type_name(ProtocolId::GRE);
    STRCMP_EQUAL("gre", name);
}

TEST(encap_layer_tests, get_tunnel_type_name_gtp)
{
    const char* name = layer::get_tunnel_type_name(ProtocolId::GTP);
    STRCMP_EQUAL("gtp", name);
}

TEST(encap_layer_tests, get_tunnel_type_name_geneve)
{
    const char* name = layer::get_tunnel_type_name(ProtocolId::GENEVE);
    STRCMP_EQUAL("geneve", name);
}

TEST(encap_layer_tests, get_tunnel_type_name_teredo)
{
    const char* name = layer::get_tunnel_type_name(ProtocolId::TEREDO);
    STRCMP_EQUAL("teredo", name);
}

TEST(encap_layer_tests, get_tunnel_type_name_unknown)
{
    const char* name = layer::get_tunnel_type_name(ProtocolId::TCP);
    STRCMP_EQUAL("unknown", name);
}

TEST(encap_layer_tests, get_encapsulation_layers_null_packet)
{
    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(nullptr);
    CHECK_TRUE(tunnels.empty());
}

TEST(encap_layer_tests, get_encapsulation_layers_no_layers)
{
    Packet p;
    p.num_layers = 0;
    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_TRUE(tunnels.empty());
}

TEST(encap_layer_tests, get_encapsulation_layers_single_layer)
{
    Packet p;
    p.num_layers = 1;
    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_TRUE(tunnels.empty());
}

TEST(encap_layer_tests, tunnel_info_default_constructor_clears_ips)
{
    // Verify TunnelInfo constructor properly initializes SfIp members
    TunnelInfo info;
    CHECK_TRUE(info.tunnel_type == ProtocolId::PROTO_NOT_SET);
    CHECK_EQUAL(0, info.src_port);
    CHECK_EQUAL(0, info.dst_port);
    CHECK_TRUE(info.ip_proto == IpProtocol::PROTO_NOT_SET);
    CHECK_FALSE(info.has_ports);
    // SfIp should be cleared (family = AF_UNSPEC)
    CHECK_EQUAL(AF_UNSPEC, info.src_ip.get_family());
    CHECK_EQUAL(AF_UNSPEC, info.dst_ip.get_family());
}

TEST(encap_layer_tests, get_encapsulation_layers_no_inner_ip)
{
    // Packet with 2 layers but no IP layer - should return empty
    // num_layers >= 2 passes first check, but no IP layer means inner_ip_idx < 0
    Packet p;
    // Use the already-allocated layers array from Packet constructor
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_NOT_SET;
    p.layers[1].prot_id = ProtocolId::ETHERTYPE_NOT_SET;
    p.num_layers = 2;
    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_TRUE(tunnels.empty());
}

TEST(encap_layer_tests, get_encapsulation_layers_tunnel_without_outer_ip)
{
    // Test the case where a tunnel protocol is found but no outer IP exists
    // This covers lines 584-585: find_outer_ip returns false, tunnel is skipped
    Packet p;
    // Layer 0: Ethernet (not an IP)
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_NOT_SET;
    p.layers[0].start = nullptr;
    // Layer 1: VXLAN tunnel (tunnel protocol without preceding IP)
    p.layers[1].prot_id = ProtocolId::VXLAN;
    p.layers[1].start = nullptr;
    // Layer 2: Inner IPv4
    p.layers[2].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[2].start = nullptr;
    p.num_layers = 3;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    // Tunnel should be skipped because no outer IP was found
    CHECK_TRUE(tunnels.empty());
}

TEST(encap_layer_tests, get_encapsulation_layers_gre_tunnel_no_ports)
{
    // Test GRE tunnel which doesn't have ports (tunnel_has_ports returns false)
    // This covers the GRE case in tunnel_has_ports
    Packet p;
    // Layer 0: Outer IPv4
    static uint8_t outer_ip4_data[20] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                                          0x40, 0x2f, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
                                          0xac, 0x10, 0x17, 0x0b};
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[0].start = outer_ip4_data;
    // Layer 1: GRE tunnel
    p.layers[1].prot_id = ProtocolId::GRE;
    p.layers[1].start = nullptr;
    // Layer 2: Inner IPv4
    p.layers[2].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[2].start = nullptr;
    p.num_layers = 3;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_EQUAL(1, tunnels.size());
    CHECK_TRUE(tunnels[0].tunnel_type == ProtocolId::GRE);
    CHECK_FALSE(tunnels[0].has_ports);  // GRE doesn't have ports
}

TEST(encap_layer_tests, get_encapsulation_layers_ipv6_outer)
{
    // Test tunnel with IPv6 outer IP
    // This covers lines 539-547 in find_outer_ip
    Packet p;
    // Layer 0: Outer IPv6
    static uint8_t outer_ip6_data[40] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,  // Version, TC, Flow, Len, NH=UDP, HL
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,  // Src: 2001:db8::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,  // Dst: 2001:db8::2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_IPV6;
    p.layers[0].start = outer_ip6_data;
    // Layer 1: UDP
    static uint8_t udp_data[8] = {0x30, 0x39, 0x17, 0xc1, 0x00, 0x08, 0x00, 0x00};  // src=12345, dst=6081
    p.layers[1].prot_id = ProtocolId::UDP;
    p.layers[1].start = udp_data;
    // Layer 2: GENEVE tunnel
    p.layers[2].prot_id = ProtocolId::GENEVE;
    p.layers[2].start = nullptr;
    // Layer 3: Inner IPv4
    p.layers[3].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[3].start = nullptr;
    p.num_layers = 4;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_EQUAL(1, tunnels.size());
    CHECK_TRUE(tunnels[0].tunnel_type == ProtocolId::GENEVE);
    CHECK_TRUE(tunnels[0].has_ports);
    CHECK_EQUAL(12345, tunnels[0].src_port);
    CHECK_EQUAL(6081, tunnels[0].dst_port);
}

TEST(encap_layer_tests, get_encapsulation_layers_multiple_tunnels)
{
    // Test packet with multiple encapsulation layers
    Packet p;
    // Layer 0: Outer IPv4
    static uint8_t outer_ip4_data[20] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                                          0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
                                          0xac, 0x10, 0x17, 0x0b};
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[0].start = outer_ip4_data;
    // Layer 1: UDP
    static uint8_t udp_data[8] = {0x30, 0x39, 0x17, 0xc1, 0x00, 0x08, 0x00, 0x00};
    p.layers[1].prot_id = ProtocolId::UDP;
    p.layers[1].start = udp_data;
    // Layer 2: VXLAN tunnel
    p.layers[2].prot_id = ProtocolId::VXLAN;
    p.layers[2].start = nullptr;
    // Layer 3: Middle IPv4
    static uint8_t mid_ip4_data[20] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                                        0x40, 0x2f, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                                        0x0a, 0x00, 0x00, 0x02};
    p.layers[3].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[3].start = mid_ip4_data;
    // Layer 4: GRE tunnel
    p.layers[4].prot_id = ProtocolId::GRE;
    p.layers[4].start = nullptr;
    // Layer 5: Inner IPv4
    p.layers[5].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[5].start = nullptr;
    p.num_layers = 6;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    // Should find 2 tunnels: GRE (innermost) and VXLAN (outermost)
    CHECK_EQUAL(2, tunnels.size());
    // First tunnel found (scanning from inner to outer) is GRE
    CHECK_TRUE(tunnels[0].tunnel_type == ProtocolId::GRE);
    CHECK_FALSE(tunnels[0].has_ports);
    // Second tunnel is VXLAN
    CHECK_TRUE(tunnels[1].tunnel_type == ProtocolId::VXLAN);
    CHECK_TRUE(tunnels[1].has_ports);
}

TEST(encap_layer_tests, get_encapsulation_layers_teredo_tunnel)
{
    // Test TEREDO tunnel type
    Packet p;
    // Layer 0: Outer IPv4
    static uint8_t outer_ip4_data[20] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                                          0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
                                          0xac, 0x10, 0x17, 0x0b};
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[0].start = outer_ip4_data;
    // Layer 1: UDP
    static uint8_t udp_data[8] = {0x0d, 0x96, 0x0d, 0x96, 0x00, 0x08, 0x00, 0x00};  // port 3478
    p.layers[1].prot_id = ProtocolId::UDP;
    p.layers[1].start = udp_data;
    // Layer 2: TEREDO tunnel
    p.layers[2].prot_id = ProtocolId::TEREDO;
    p.layers[2].start = nullptr;
    // Layer 3: Inner IPv6
    p.layers[3].prot_id = ProtocolId::ETHERTYPE_IPV6;
    p.layers[3].start = nullptr;
    p.num_layers = 4;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_EQUAL(1, tunnels.size());
    CHECK_TRUE(tunnels[0].tunnel_type == ProtocolId::TEREDO);
    CHECK_TRUE(tunnels[0].has_ports);  // TEREDO has ports
    CHECK_EQUAL(3478, tunnels[0].src_port);
    CHECK_EQUAL(3478, tunnels[0].dst_port);
}

TEST(encap_layer_tests, get_encapsulation_layers_gtp_tunnel)
{
    // Test GTP tunnel type
    Packet p;
    // Layer 0: Outer IPv4
    static uint8_t outer_ip4_data[20] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                                          0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
                                          0xac, 0x10, 0x17, 0x0b};
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[0].start = outer_ip4_data;
    // Layer 1: UDP
    static uint8_t udp_data[8] = {0x08, 0x68, 0x08, 0x68, 0x00, 0x08, 0x00, 0x00};  // port 2152
    p.layers[1].prot_id = ProtocolId::UDP;
    p.layers[1].start = udp_data;
    // Layer 2: GTP tunnel
    p.layers[2].prot_id = ProtocolId::GTP;
    p.layers[2].start = nullptr;
    // Layer 3: Inner IPv4
    p.layers[3].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[3].start = nullptr;
    p.num_layers = 4;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_EQUAL(1, tunnels.size());
    CHECK_TRUE(tunnels[0].tunnel_type == ProtocolId::GTP);
    CHECK_TRUE(tunnels[0].has_ports);  // GTP has ports
    CHECK_EQUAL(2152, tunnels[0].src_port);
    CHECK_EQUAL(2152, tunnels[0].dst_port);
}

TEST(encap_layer_tests, get_encapsulation_layers_tunnel_with_non_ip_layers)
{
    // Test tunnel with non-IP/non-UDP layers in between (covers default case in find_outer_ip)
    Packet p;
    // Layer 0: Outer IPv4
    static uint8_t outer_ip4_data[20] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                                          0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
                                          0xac, 0x10, 0x17, 0x0b};
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[0].start = outer_ip4_data;
    // Layer 1: Some non-IP, non-UDP layer (e.g., Ethernet)
    p.layers[1].prot_id = ProtocolId::ETHERTYPE_NOT_SET;
    p.layers[1].start = nullptr;
    // Layer 2: UDP
    static uint8_t udp_data[8] = {0x30, 0x39, 0x17, 0xc1, 0x00, 0x08, 0x00, 0x00};
    p.layers[2].prot_id = ProtocolId::UDP;
    p.layers[2].start = udp_data;
    // Layer 3: GENEVE tunnel
    p.layers[3].prot_id = ProtocolId::GENEVE;
    p.layers[3].start = nullptr;
    // Layer 4: Inner IPv4
    p.layers[4].prot_id = ProtocolId::ETHERTYPE_IPV4;
    p.layers[4].start = nullptr;
    p.num_layers = 5;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    CHECK_EQUAL(1, tunnels.size());
    CHECK_TRUE(tunnels[0].tunnel_type == ProtocolId::GENEVE);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
