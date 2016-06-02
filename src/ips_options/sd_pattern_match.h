//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

// sd_pattern_match.h author Ryan Jordan

#ifndef SD_PATTERN_MATCH_H
#define SD_PATTERN_MATCH_H

#include <iostream>
#include <stdint.h>
#include "utils/util.h"

#define SD_SOCIAL_PATTERN          "\\b\\d{3}-\\d{2}-\\d{4}\\b"
#define SD_SOCIAL_NODASHES_PATTERN "\\b\\d{9}\\b"
#define SD_CREDIT_PATTERN_ALL      "\\b\\d{4} ?-?\\d{4} ?-?\\d{2} ?-?\\d{2} ?-?\\d{3}\\d?\\b"

class SdOptionData
{
public:
    friend class SdPatternOption;

    SdOptionData(std::string pattern, bool obfuscate);

    ~SdOptionData()
    { snort_free(pattern); }

    void ExpandBrackets();
    bool match(const uint8_t* const buf, uint16_t* const buf_index, uint16_t buflen);

private:
    char* pattern;
    int (*validate)(const uint8_t* buf, uint32_t buflen) = nullptr;
    bool obfuscate_pii = false;
};

#endif

