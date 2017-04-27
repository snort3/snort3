//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_mock_definitions.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_MOCK_DEFINITIONS_H_
#define APPID_MOCK_DEFINITIONS_H_

class Inspector;
struct ThirdPartyAppIDModule;

AppIdConfig* pAppidActiveConfig = nullptr;
THREAD_LOCAL ThirdPartyAppIDModule* thirdparty_appid_module = nullptr;

char* snort_strndup(const char* src, size_t dst_size)
{
    return strndup(src, dst_size);
}

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}

void Field::set(int32_t length, const uint8_t* start, bool own_the_buffer_)
{
    strt = start;
    len = length;
    own_the_buffer = own_the_buffer_;
}

Field global_field;

#ifdef DEBUG_MSGS
void Debug::print(const char*, int, uint64_t, const char*, ...) { }
#endif

int ServiceDiscovery::add_ftp_service_state(AppIdSession&)
{
    return 0;
}

#endif

