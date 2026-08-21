//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// checksum_test.cc author Claude <noreply@anthropic.com>

// Regression coverage for the size_t length-underflow hardening in the
// checksum header helpers. When a corrupted/short buffer is
// passed a length smaller than the fixed header being subtracted,
// add_tcp_header/add_udp_header/add_ip_header used to do an unconditional
// "len -= N", underflowing the size_t and causing cksum_add() to scan
// ~2^64 bytes -> OOB read -> SIGSEGV. These tests confirm the guarded
// helpers instead bail out safely and that valid inputs are unaffected.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/ip/checksum.h"

#include "utils/endian.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace checksum;

// A 16-byte scratch buffer. The underflow-guard tests deliberately pass a
// declared length smaller than the fixed header being consumed (e.g. len=4 vs a
// 20-byte TCP header). Without the guard the helper's unconditional "len -= N"
// would underflow the size_t to a huge value and cksum_add() would walk off the
// end of this buffer -- i.e. the test crashes instead of failing cleanly. With
// the guard in place the helper never dereferences the header and returns with
// len == 0.
static const uint8_t short_buf[16] =
{ 0x22, 0x11, 0x44, 0x33, 0x66, 0x55, 0x88, 0x77,
  0xaa, 0x99, 0xcc, 0xbb, 0xee, 0xdd, 0x00, 0xff };

//--------------------------------------------------------------------------
// detail helper guards: short length must not underflow
//--------------------------------------------------------------------------

TEST_GROUP(checksum_header_guards) { };

TEST(checksum_header_guards, tcp_header_short_len_no_underflow)
{
    const uint8_t* d = short_buf;
    std::size_t len = 4;            // < TCP_MIN_HEADER_LEN (20)
    uint32_t cksum = 0;

    detail::add_tcp_header(d, len, cksum);

    // Guard must zero the length (safe no-op downstream), not wrap it.
    CHECK_EQUAL(0u, len);
}

TEST(checksum_header_guards, udp_header_short_len_no_underflow)
{
    const uint8_t* d = short_buf;
    std::size_t len = 4;            // < UDP_MIN_HEADER_LEN (8)
    uint32_t cksum = 0;

    detail::add_udp_header(d, len, cksum);

    CHECK_EQUAL(0u, len);
}

TEST(checksum_header_guards, ip_header_short_len_no_underflow)
{
    const uint8_t* d = short_buf;
    std::size_t len = 4;            // < IP_MIN_HEADER_LEN (20)
    uint32_t cksum = 0;

    detail::add_ip_header(d, len, cksum);

    CHECK_EQUAL(0u, len);
}

TEST(checksum_header_guards, tcp_header_zero_len_no_underflow)
{
    const uint8_t* d = short_buf;
    std::size_t len = 0;
    uint32_t cksum = 0;

    detail::add_tcp_header(d, len, cksum);

    CHECK_EQUAL(0u, len);
}

//--------------------------------------------------------------------------
// public cksum entry points.
//--------------------------------------------------------------------------

TEST_GROUP(checksum_public_api_guards) { };

// TcpCodec::update() passes updated_len == 4 (dsize 0 + a bogus hlen of 4)
// into tcp_cksum(). Verify that this does not underflow.
TEST(checksum_public_api_guards, tcp_cksum_ip4_short_len)
{
    Pseudoheader ph;
    ph.hdr.sip = 0;
    ph.hdr.dip = 0;
    ph.hdr.zero = 0;
    ph.hdr.protocol = IpProtocol::TCP;
    ph.hdr.len = 0;

    // If this underflows we never return; reaching the assert proves the fix.
    (void)tcp_cksum(short_buf, 4, ph);
    CHECK(true);
}

TEST(checksum_public_api_guards, tcp_cksum_ip6_short_len)
{
    Pseudoheader6 ph6{};

    (void)tcp_cksum(short_buf, 4, ph6);
    CHECK(true);
}

TEST(checksum_public_api_guards, udp_cksum_ip4_short_len)
{
    Pseudoheader ph;
    ph.hdr.sip = 0;
    ph.hdr.dip = 0;
    ph.hdr.zero = 0;
    ph.hdr.protocol = IpProtocol::UDP;
    ph.hdr.len = 0;

    (void)udp_cksum(short_buf, 4, ph);
    CHECK(true);
}

TEST(checksum_public_api_guards, ip_cksum_short_len)
{
    (void)ip_cksum(short_buf, 4);
    CHECK(true);
}

//--------------------------------------------------------------------------
// valid inputs are unchanged by the guard
//--------------------------------------------------------------------------

TEST_GROUP(checksum_valid_inputs) { };

// A well-formed 20-byte TCP header (no payload) must still checksum. The exact
// value is not important here; what matters is that the guarded path produces
// the same result the original (unguarded) code would have -- i.e. the guard is
// inert for len >= header size. We verify the standard property that summing a
// buffer together with its own computed checksum yields 0 (mod ones-complement).
TEST(checksum_valid_inputs, tcp_min_header_checksum_verifies)
{
    // 20-byte (10 x uint16) minimal TCP header, arbitrary but fixed contents.
    uint16_t tcph[10] =
    { 0x0050, 0xd431, 0x0000, 0x0001, 0x0000, 0x0000, 0x5002, 0x2000, 0x0000, 0x0000 };

    Pseudoheader ph;
    ph.hdr.sip = 0x0100007f;   // 127.0.0.1
    ph.hdr.dip = 0x0100007f;
    ph.hdr.zero = 0;
    ph.hdr.protocol = IpProtocol::TCP;
    ph.hdr.len = htons(20);

    uint16_t sum = tcp_cksum(tcph, 20, ph);

    // Write the checksum back and re-verify: a correct checksum makes the
    // recomputed sum over the segment come out to 0.
    tcph[8] = sum;
    CHECK_EQUAL(0, tcp_cksum(tcph, 20, ph));
}

TEST(checksum_valid_inputs, ip_min_header_checksum_verifies)
{
    // 20-byte minimal IPv4 header, checksum field (word 5) zeroed.
    uint16_t iph[10] =
    { 0x4500, 0x0028, 0x1c46, 0x4000, 0x4006, 0x0000, 0x007f, 0x0000, 0x0100, 0x0000 };

    uint16_t sum = ip_cksum(iph, 20);
    iph[5] = sum;
    CHECK_EQUAL(0, ip_cksum(iph, 20));
}

//--------------------------------------------------------------------------
// main
//--------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
