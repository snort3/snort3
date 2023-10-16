//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// rna_fingerprint.h author Silviu Minut <sminut@cisco.com>

#ifndef RNA_FP_H
#define RNA_FP_H

#include <cstdint>
#include <string>
#include <vector>

#include "main/snort_types.h"

#define FP_SYN_KEY          "SYN"
#define FP_RANDOM_KEY       "R"
#define FP_DONT_CARE_KEY    "X"
#define FP_SYN_TS_KEY       "TS"

#define MAXIMUM_FP_HOPS 32

namespace snort
{

class FpFingerprint
{
public:

    enum FpType
    {
        FP_TYPE_DERIVED = 0,
        FP_TYPE_SERVER = 1,
        FP_TYPE_CLIENT = 2,
        FP_TYPE_SMB = 3,
        FP_TYPE_DHCP = 4,
        FP_TYPE_USER = 5,
        FP_TYPE_SCAN = 6,
        FP_TYPE_APP = 7,
        FP_TYPE_CONFLICT = 8,
        FP_TYPE_MOBILE = 9,
        FP_TYPE_SERVER6 = 10,
        FP_TYPE_CLIENT6 = 11,
        FP_TYPE_DHCP6 = 12,
        FP_TYPE_USERAGENT = 13,
        FP_TYPE_CPE = 14,
        MAX_FP_TYPES = 15
    };

    uint32_t fpid = 0;
    uint32_t fp_type = 0;
    std::string fpuuid;
    uint8_t ttl = 0;

    virtual ~FpFingerprint() = default;

    virtual void clear()
    {
        fpid = 0;
        fp_type = 0;
        fpuuid.clear();
        ttl = 0;
    }
};

enum FpElementType
{
    INVALID = -1,
    RANGE = 1,
    INCREMENT,
    SYN_MATCH,
    RANDOM,
    DONT_CARE,
    SYNTS
};

class SO_PUBLIC FpElement
{
public:

    FpElement() = default;
    FpElement(const std::string&);

    FpElement& operator=(const FpElement& fpe) = default;
    FpElement& operator=(const std::string& str);
    bool operator==(const FpElement& y) const;

    FpElementType type;
    union
    {
        int value;
        struct
        {
            int min;
            int max;
        } range;
    } d;

private:
    void parse_value(const std::string&);
};

}

enum UserAgentInfoType
{
    OS_INFO,
    DEVICE_INFO,
    JAIL_BROKEN_INFO,
    JAIL_BROKEN_HOST
};

class RawFingerprint
{
public:

    uint32_t fpid = 0;
    uint32_t fp_type = 0;
    std::string fpuuid;
    uint8_t ttl = 0;

    std::string tcp_window;
    std::string mss;
    std::string id;
    std::string topts;
    std::string ws;
    bool df = false;

    UserAgentInfoType ua_type = OS_INFO;
    std::vector<std::string> user_agent;
    std::string host_name;
    std::string device;

    std::string dhcp55;
    std::string dhcp60;

    uint16_t smb_major;
    uint16_t smb_minor;
    uint32_t smb_flags;

    void clear()
    {
        fpid = 0;
        fp_type = 0;
        fpuuid.clear();
        ttl = 0;
        tcp_window.clear();
        mss.clear();
        id.clear();
        topts.clear();
        ws.clear();
        df = false;
        ua_type = OS_INFO;
        user_agent.clear();
        host_name.clear();
        device.clear();
        dhcp55.clear();
        dhcp60.clear();
        smb_major = 0;
        smb_minor = 0;
        smb_flags = 0;
    }
};

#endif
