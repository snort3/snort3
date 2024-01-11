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

// rna_fingerprint.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_fingerprint.h"

#include <cassert>
#include <cstring>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

FpElement::FpElement(const string& str) : type(FpElementType::INVALID)
{
    parse_value(str);
}

FpElement& FpElement::operator=(const std::string& str)
{
    type = FpElementType::INVALID;
    parse_value(str);
    return *this;
}

bool FpElement::operator==(const FpElement& y) const
{
    const FpElement& x=*this;
    if (x.type != y.type)
        return false;

    switch (x.type)
    {
    case FpElementType::RANGE:
        return (x.d.value == y.d.value) &&
            (x.d.range.min == y.d.range.min) &&
            (x.d.range.max == y.d.range.max);

    case FpElementType::SYN_MATCH:
    case FpElementType::INCREMENT:
        return x.d.value == y.d.value;

    default:
        break;
    }
    return true;
}

void FpElement::parse_value(const std::string& str)
{
    FpElement& v=*this;

    v.type = FpElementType::INVALID;

    const char* data = str.c_str();
    for (; *data && isspace(*data); data++);

    if (*data == '+')
    {
        v.type = FpElementType::INCREMENT;
        data++;
        v.d.value = strtol(data, nullptr, 10);
        return;
    }
    else if (strlen(data) >= sizeof(FP_SYN_KEY)-1 &&
        !strncmp(data, FP_SYN_KEY, sizeof(FP_SYN_KEY)-1))
    {
        v.type = FpElementType::SYN_MATCH;
        data += sizeof(FP_SYN_KEY)-1;
        if (*data != '-')
        {
            v.d.value = 0;
            return;
        }
        data++;
        v.d.value = strtol(data, nullptr, 10);
        return;
    }
    else if (strlen(data) >= sizeof(FP_RANDOM_KEY)-1 &&
        !strncmp(data, FP_RANDOM_KEY, sizeof(FP_RANDOM_KEY)-1))
    {
        v.type = FpElementType::RANDOM;
        return;
    }
    else if (strlen(data) >= sizeof(FP_DONT_CARE_KEY)-1 &&
        !strncmp(data, FP_DONT_CARE_KEY, sizeof(FP_DONT_CARE_KEY)-1))
    {
        v.type = FpElementType::DONT_CARE;
        return;
    }
    else if (strlen(data) >= sizeof(FP_SYN_TS_KEY)-1 &&
        !strncmp(data, FP_SYN_TS_KEY, sizeof(FP_SYN_TS_KEY)-1))
    {
        v.type = FpElementType::SYNTS;
        return;
    }

    // this converts "-1" to [0,1], in agreement with snort 2
    if (const char* r=strchr(data, '-'))
    {
        v.type = FpElementType::RANGE;
        string left(data, r);
        string right(++r);
        v.d.range.min = strtol(left.c_str(), nullptr, 10);
        v.d.range.max = strtol(right.c_str(), nullptr, 10);
    }
    else
    {
        v.type = FpElementType::RANGE;
        v.d.range.min = strtol(data, nullptr, 10);
        v.d.range.max = v.d.range.min;
    }

    assert(v.type != FpElementType::INVALID);
}

#ifdef UNIT_TEST

TEST_CASE("FpElement", "[rna_fingerprint]")
{
    FpElement fpe;
    FpElement fpe_test;

    // RANGE, single value
    fpe_test = "10";
    fpe.type = FpElementType::RANGE;
    fpe.d.value = 10;
    fpe.d.range.min = 10;
    fpe.d.range.max = 10;
    CHECK(fpe == fpe_test);

    // RANGE, range
    fpe_test = "1-20";
    fpe.type = FpElementType::RANGE;
    fpe.d.value = 0;
    fpe.d.range.min = 1;
    fpe.d.range.max = 20;
    CHECK(fpe == fpe_test);

    // INCREMENT
    fpe_test = "+20";
    fpe.type = FpElementType::INCREMENT;
    fpe.d.value = 20;
    CHECK(fpe == fpe_test);

    // SYN_MATCH, key only
    fpe_test = FP_SYN_KEY;
    fpe.type = FpElementType::SYN_MATCH;
    fpe.d.value = 0;
    CHECK(fpe == fpe_test);

    // SYN_MATCH, key and value
    fpe_test = string(FP_SYN_KEY) + "-20";
    fpe.type = FpElementType::SYN_MATCH;
    fpe.d.value = 20;
    CHECK(fpe == fpe_test);

    fpe_test = FP_RANDOM_KEY;
    fpe.type = FpElementType::RANDOM;
    fpe.d.value = 20;
    CHECK(fpe == fpe_test);

    fpe_test = FP_DONT_CARE_KEY;
    fpe.type = FpElementType::DONT_CARE;
    fpe.d.value = 20;
    CHECK(fpe == fpe_test);

    fpe_test = FP_SYN_TS_KEY;
    fpe.type = FpElementType::SYNTS;
    fpe.d.value = 20;
    CHECK(fpe == fpe_test);
}

#endif

