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

// rna_fingerprint.h author Silviu Minut <sminut@cisco.com>

#ifndef RNA_FINGERPRINT_H
#define RNA_FINGERPRINT_H

#include <cstdint>
#include <string>
#include <uuid/uuid.h>

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
        FINGERPRINT_TYPE_DERIVED = 0,
        FINGERPRINT_TYPE_SERVER = 1,
        FINGERPRINT_TYPE_CLIENT = 2,
        FINGERPRINT_TYPE_SMB = 3,
        FINGERPRINT_TYPE_DHCP = 4,
        FINGERPRINT_TYPE_USER = 5,
        FINGERPRINT_TYPE_SCAN = 6,
        FINGERPRINT_TYPE_APP = 7,
        FINGERPRINT_TYPE_CONFLICT = 8,
        FINGERPRINT_TYPE_MOBILE = 9,
        FINGERPRINT_TYPE_SERVER6 = 10,
        FINGERPRINT_TYPE_CLIENT6 = 11,
        FINGERPRINT_TYPE_DHCP6 = 12,
        FINGERPRINT_TYPE_USERAGENT = 13,
        MAX_FINGERPRINT_TYPES = 14
    };

    uint32_t fpid = 0;
    uint32_t fp_type = 0;
    uuid_t fpuuid;
    uint8_t ttl = 0;

    virtual ~FpFingerprint() { }

    virtual void clear()
    {
        fpid = 0;
        fp_type = 0;
        uuid_clear(fpuuid);
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
        df=false;
    }

};

#endif
