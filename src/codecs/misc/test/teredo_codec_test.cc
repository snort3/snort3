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
// teredo_codec_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>
#include <cstring>

#include "main/thread_config.h"

#include "../cd_teredo.cc"

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
    void Codec::codec_event(const CodecData&, CodecSid) { }

    unsigned get_instance_id() { return 0; }
    unsigned ThreadConfig::get_instance_max() { return 1; }
// LCOV_EXCL_STOP
}

class ExactPayload
{
public:
    template <size_t N>
    explicit ExactPayload(const uint8_t (&src)[N]) : len(N)
    {
        data = static_cast<uint8_t*>(std::malloc(N));
        CHECK(data);
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

static bool decode_teredo_payload(const ExactPayload& payload)
{
    TeredoCodec codec;
    CodecData codec_data(nullptr, ProtocolId::TEREDO);
    DecodeData decode_data;
    decode_data.sp = teredo::TEREDO_PORT;
    decode_data.dp = 6666;
    RawData raw_data(nullptr, payload.bytes(), payload.size());

    return codec.decode(raw_data, codec_data, decode_data);
}

TEST_GROUP(teredo_codec_tests)
{
};

TEST(teredo_codec_tests, rejects_payload_ending_after_auth_indicator)
{
    static const uint8_t auth_only_min[] =
    {
        0x00, 0x01, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF, 0x11, 0x22, 0x33
    };

    ExactPayload payload(auth_only_min);

    CHECK_FALSE(decode_teredo_payload(payload));
}

TEST(teredo_codec_tests, rejects_payload_ending_after_origin_indicator)
{
    static const uint8_t origin_only_len[] =
    {
        0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    ExactPayload payload(origin_only_len);

    CHECK_FALSE(decode_teredo_payload(payload));
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
