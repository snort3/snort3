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

// rna_fingerprint_udp.h author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifndef RNA_FINGERPRINT_UDP_H
#define RNA_FINGERPRINT_UDP_H

#include <string>
#include <vector>

#include "rna_fingerprint.h"

namespace snort
{
class SO_PUBLIC DHCPFingerprint : public FpFingerprint
{
public:
    DHCPFingerprint() = default;
    DHCPFingerprint(const RawFingerprint& rfp);
    std::vector<FpElement> dhcp55;
    std::string dhcp60;
};

struct FpDHCPKey
{
    unsigned dhcp55_len;
    unsigned dhcp60_len;
    const uint8_t* dhcp55;
    const uint8_t* dhcp60;
};

class SO_PUBLIC UdpFpProcessor
{
public:
    void push(const RawFingerprint& rfp);
    const DHCPFingerprint* match_dhcp_fingerprint(const FpDHCPKey&) const;

    void push_dhcp_fp(DHCPFingerprint& dhcp_fp)
    {
        dhcp_fps.emplace_back(dhcp_fp);
    }
private:
    std::vector<DHCPFingerprint> dhcp_fps;
};

}

snort::UdpFpProcessor* get_udp_fp_processor();
SO_PUBLIC void set_udp_fp_processor(snort::UdpFpProcessor*);
#endif
