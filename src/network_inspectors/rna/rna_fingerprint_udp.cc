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

// rna_fingerprint_udp.cc author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_fingerprint_udp.h"

#include <algorithm>
#include <sstream>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#include "main/thread.h"
#include "pub_sub/dhcp_events.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL UdpFpProcessor* udp_fp_processor = nullptr;

void set_udp_fp_processor(UdpFpProcessor* processor)
{
    udp_fp_processor = processor;
}

UdpFpProcessor* get_udp_fp_processor()
{
    return udp_fp_processor;
}

static void parse_fp_element(const string& data, vector<FpElement>& fpe)
{
    istringstream in(data);
    string tok;
    while ( in >> tok )
        fpe.emplace_back(tok);
}

DHCPFingerprint::DHCPFingerprint(const RawFingerprint& rfp)
{
    fpid = rfp.fpid;
    fpuuid = rfp.fpuuid;
    fp_type = rfp.fp_type;
    if (!rfp.dhcp55.empty())
        parse_fp_element(rfp.dhcp55, dhcp55);
    if (!rfp.dhcp60.empty())
        dhcp60 = rfp.dhcp60;
}

void UdpFpProcessor::push(const RawFingerprint& rfp)
{
    if (rfp.fp_type == FpFingerprint::FpType::FP_TYPE_DHCP)
    {
        DHCPFingerprint dhcp_fp(rfp);
        if (dhcp_fp.dhcp55.size() > DHCP_OP55_MAX_SIZE)
            return;
        push_dhcp_fp(dhcp_fp);
    }
}

static bool match_dhcp_options(const vector<FpElement>& options, const uint8_t* key_options)
{
    for (const auto& op : options)
    {
        if (op.d.value != *key_options++)
            return false;
    }
    return true;
}

const DHCPFingerprint* UdpFpProcessor::match_dhcp_fingerprint(const FpDHCPKey& key) const
{
    if (key.dhcp55_len == 0 || key.dhcp55_len > DHCP_OP55_MAX_SIZE)
        return nullptr;
    uint32_t fptype = FpFingerprint::FpType::FP_TYPE_DHCP;
    for (const auto& fp: dhcp_fps)
    {
        if (fptype == fp.fp_type and fp.dhcp55.size() == key.dhcp55_len and
            match_dhcp_options(fp.dhcp55, key.dhcp55))
        {
            if (key.dhcp60 and !fp.dhcp60.empty())
            {
                if(fp.dhcp60.size() == key.dhcp60_len and
                    !fp.dhcp60.compare((const char*) (key.dhcp60)))
                    return &fp;
            }
            else if (fp.dhcp60.empty())
                return &fp;
        }
    }
    return nullptr;
}

#ifdef UNIT_TEST

TEST_CASE("match_dhcp_fingerprint", "[rna_fingerprint_udp]")
{
    set_udp_fp_processor(new UdpFpProcessor);
    UdpFpProcessor* processor = get_udp_fp_processor();

    RawFingerprint rawfp;
    rawfp.fpid = 111;
    rawfp.fp_type = 4;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789111";
    rawfp.dhcp55 = "1 3 15 28 225";
    rawfp.dhcp60 = "dhcp 5.1.2";
    processor->push(rawfp);

    FpDHCPKey key;
    key.dhcp55_len = 0;
    key.dhcp60 = (const uint8_t*) "dhcp 5.1.2";
    key.dhcp60_len = 10;
    // no dhcp55, only dhcp60 option, returns null
    CHECK(processor->match_dhcp_fingerprint(key) == nullptr);

    rawfp.fpid = 222;
    rawfp.fp_type = 4;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789222";
    rawfp.dhcp55 = "1 2 45 121";
    rawfp.dhcp60 = "dhcp 5.1.3";
    processor->push(rawfp);

    uint8_t op55[] = {1, 2, 45, 121};
    key.dhcp55 = op55;
    key.dhcp55_len = 4;
    key.dhcp60 = (const uint8_t*) "dhcp 5.0";
    key.dhcp60_len = 8;
    //dhcp60 doesn't match, returns null
    CHECK(processor->match_dhcp_fingerprint(key) == nullptr);
}
#endif
