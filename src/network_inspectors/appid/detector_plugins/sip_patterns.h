//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// sip_patterns.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef SIP_PATTERNS_H
#define SIP_PATTERNS_H

#include "appid_utils/sf_mlmp.h"
#include "application_ids.h"

class OdpContext;

struct SipUaUserData
{
    AppId client_id;
    char* client_version;
};

struct DetectorAppSipPattern
{
    tMlpPattern pattern;
    SipUaUserData user_data;
    DetectorAppSipPattern* next;
};

class SipPatternMatchers
{
public:
    ~SipPatternMatchers();
    int add_ua_pattern(AppId, const char*, const char*);
    int add_server_pattern(AppId, const char*, const char*);
    int get_client_from_ua(const char*, uint32_t, AppId&, char*&);
    int get_client_from_server(const char*, uint32_t, AppId&, char*&);
    void finalize_patterns(OdpContext&);
    void reload_patterns();

private:
    static const int PATTERN_PART_MAX = 10;
    tMlmpPattern patterns[PATTERN_PART_MAX] = { { nullptr, 0, 0 } };
    tMlmpTree* sip_ua_matcher = nullptr;
    DetectorAppSipPattern* sip_ua_list = nullptr;
    tMlmpTree* sip_server_matcher = nullptr;
    DetectorAppSipPattern* sip_server_list = nullptr;
};

#endif
