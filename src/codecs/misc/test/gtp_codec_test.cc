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
// gtp_codec_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>
#include <cstring>

#include "main/thread_config.h"

#include "../cd_gtp.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

// LCOV_EXCL_START
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }
// LCOV_EXCL_STOP

namespace snort
{
    bool SnortConfig::tunnel_bypass_enabled(unsigned short) const { return false; }

// LCOV_EXCL_START
    bool TextLog_Print(TextLog* const, const char*, ...) { return false; }
    // cppcheck-suppress functionStatic ; definition of a real Codec member, not a free function
    void Codec::codec_event(const CodecData&, CodecSid) { }

    unsigned get_instance_id() { return 0; }
    unsigned ThreadConfig::get_instance_max() { return 1; }
// LCOV_EXCL_STOP
}

// A heap-backed, exactly-sized packet buffer so ASAN faults on a single
// byte read past the end (the plain build would not).
class ExactPayload
{
public:
    template <size_t N>
    explicit ExactPayload(const uint8_t (&src)[N]) : len(N)
    {
        data = static_cast<uint8_t*>(std::malloc(N));
        CHECK(data);
        // cppcheck-suppress nullPointerOutOfMemory ; CHECK() aborts the test on a null allocation
        std::memcpy(data, src, N);
    }

    ~ExactPayload()
    { std::free(data); }

    const uint8_t* bytes() const { return data; }
    size_t size() const { return len; }

private:
    size_t len = 0;
    uint8_t* data = nullptr;
};

static bool decode_gtp_payload(const ExactPayload& payload, CodecData& codec_data)
{
    GtpCodec codec;
    DecodeData decode_data;
    RawData raw_data(nullptr, payload.bytes(), payload.size());

    return codec.decode(raw_data, codec_data, decode_data);
}

TEST_GROUP(gtp_codec_tests)
{
};

// Regression for cd_gtp OOB read of the inner-IP version byte when a
// well-formed GTP header exactly fills the packet (no inner payload).
TEST(gtp_codec_tests, gtpv1_header_fills_packet_no_inner_read)
{
    // GTP v1, PDU (type 255), version-1 flag bit set, no optional fields,
    // reported length 0 -> header is the whole 8-byte datagram, so there
    // is no inner-IP version byte to read.
    static const uint8_t gtpv1_no_payload[] =
    {
        0x30, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ExactPayload payload(gtpv1_no_payload);

    CodecData codec_data(nullptr, ProtocolId::GTP);
    CHECK(decode_gtp_payload(payload, codec_data));

    // Header-only: no inner layer, so CODEC_ENCAP_LAYER stays clear while
    // the tunnel is still marked non-IP.
    CHECK((codec_data.codec_flags & CODEC_ENCAP_LAYER) == 0);
    CHECK(codec_data.codec_flags & CODEC_NON_IP_TUNNEL);
}

// A v0 header that exactly fills the packet: the 20-byte v0 header with a
// reported length of 0 is the whole datagram, likewise no inner byte.
TEST(gtp_codec_tests, gtpv0_header_fills_packet_no_inner_read)
{
    static const uint8_t gtpv0_no_payload[] =
    {
        0x10, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    ExactPayload payload(gtpv0_no_payload);

    CodecData codec_data(nullptr, ProtocolId::GTP);
    CHECK(decode_gtp_payload(payload, codec_data));

    CHECK((codec_data.codec_flags & CODEC_ENCAP_LAYER) == 0);
    CHECK(codec_data.codec_flags & CODEC_NON_IP_TUNNEL);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
