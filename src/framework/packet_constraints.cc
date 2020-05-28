//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// packet_constraints.cc author Serhii Lysenko <selysenk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_constraints.h"

#include "protocols/packet.h"

#include <cstring>

namespace {

inline bool match(const snort::PacketConstraints& cs, const snort::SfIp& sip,
    const snort::SfIp& dip, uint16_t sport, uint16_t dport)
{
    using SetBits = snort::PacketConstraints::SetBits;

    return (!(cs.set_bits & SetBits::SRC_PORT) or (sport == cs.src_port)) and
        (!(cs.set_bits & SetBits::DST_PORT) or (dport == cs.dst_port)) and
        (!(cs.set_bits & SetBits::SRC_IP) or (sip == cs.src_ip)) and
        (!(cs.set_bits & SetBits::DST_IP) or (dip == cs.dst_ip));
}

} // namespace

using namespace snort;

bool PacketConstraints::operator==(const PacketConstraints& other) const
{
    return set_bits == other.set_bits
        and ip_proto == other.ip_proto
        and src_port == other.src_port
        and dst_port == other.dst_port
        and src_ip == other.src_ip
        and dst_ip == other.dst_ip;
}

bool PacketConstraints::packet_match(const Packet& p) const
{
    if ( !p.has_ip() )
        return false;

    if ( (set_bits & SetBits::IP_PROTO) and (p.get_ip_proto_next() != ip_proto) )
        return false;

    const auto& sip = *p.ptrs.ip_api.get_src();
    const auto& dip = *p.ptrs.ip_api.get_dst();
    const auto sp = p.ptrs.sp;
    const auto dp = p.ptrs.dp;

    return match(*this, sip, dip, sp, dp) or match(*this, dip, sip, dp, sp);
}

bool PacketConstraints::flow_match(const Flow& f) const
{
    if ( (set_bits & SetBits::IP_PROTO) and
        (IpProtocol(f.ip_proto) != ip_proto) )
        return false;

    return match(*this, f.client_ip, f.server_ip, f.client_port, f.server_port);
}

#ifdef UNIT_TEST

#include <catch/snort_catch.h>

TEST_CASE("Packet constraints matching", "[framework]")
{
    PacketConstraints cs;

    const auto proto = IpProtocol::TCP;
    const uint16_t sport = 100;
    const uint16_t dport = 200;
    snort::SfIp sip, dip;
    sip.set("10.1.1.1");
    dip.set("10.1.1.2");


    SECTION("full match")
    {
        cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
        cs.set_bits |= PacketConstraints::SetBits::SRC_PORT;
        cs.set_bits |= PacketConstraints::SetBits::DST_PORT;
        cs.set_bits |= PacketConstraints::SetBits::SRC_IP;
        cs.set_bits |= PacketConstraints::SetBits::DST_IP;

        cs.ip_proto = proto;
        cs.src_port = sport;
        cs.dst_port = dport;
        cs.src_ip = sip;
        cs.dst_ip = dip;

        CHECK( match(cs, sip, dip, sport, dport) );
    }

    SECTION("backwards")
    {
        cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
        cs.set_bits |= PacketConstraints::SetBits::SRC_PORT;
        cs.set_bits |= PacketConstraints::SetBits::DST_PORT;
        cs.set_bits |= PacketConstraints::SetBits::SRC_IP;
        cs.set_bits |= PacketConstraints::SetBits::DST_IP;

        cs.ip_proto = proto;
        cs.src_port = sport;
        cs.dst_port = dport;
        cs.src_ip = sip;
        cs.dst_ip = dip;

        CHECK( !match(cs, dip, sip, dport, sport) );
    }

    SECTION("any ip")
    {
        cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
        cs.set_bits |= PacketConstraints::SetBits::SRC_PORT;
        cs.set_bits |= PacketConstraints::SetBits::DST_PORT;

        cs.ip_proto = proto;
        cs.src_port = sport;
        cs.dst_port = dport;

        CHECK( match(cs, sip, dip, sport, dport) );
    }

    SECTION("any port")
    {
        cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
        cs.set_bits |= PacketConstraints::SetBits::SRC_IP;
        cs.set_bits |= PacketConstraints::SetBits::DST_IP;

        cs.ip_proto = proto;
        cs.src_ip = sip;
        cs.dst_ip = dip;

        CHECK( match(cs, sip, dip, sport, dport) );
    }

    SECTION("any src")
    {
        cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
        cs.set_bits |= PacketConstraints::SetBits::DST_PORT;
        cs.set_bits |= PacketConstraints::SetBits::DST_IP;

        cs.ip_proto = proto;
        cs.dst_port = dport;
        cs.dst_ip = dip;

        CHECK( match(cs, sip, dip, sport, dport) );
    }

}

#endif

