//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// sip_roptions.h author Hui Cao <huica@cisco.com>

#ifndef SIP_ROPTIONS_H
#define SIP_ROPTIONS_H

// Definitions of sip rule option structures.

#include "sip_config.h"

#define SIP_NUM_STAT_CODE_MAX 20

struct SIP_Roptions
{
    const char* method_data;
    uint16_t method_len;

    uint16_t status_code;       // sip_stat_code data

    const uint8_t* header_data; // Set to NULL if not applicable
    uint16_t header_len;

    const uint8_t* body_data;   // Set to NULL if not applicable
    uint16_t body_len;
};

struct SipMethodRuleOptData
{
    int flags;
    int mask;
};

struct SipStatCodeRuleOptData
{
    uint16_t stat_codes[SIP_NUM_STAT_CODE_MAX];
};

#endif

