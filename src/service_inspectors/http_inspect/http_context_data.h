//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_context_data.h author Bhagya Tholpady <bbantwal@cisco.com>

#ifndef HTTP_CONTEXT_DATA_H
#define HTTP_CONTEXT_DATA_H

#include "detection/ips_context_data.h"

class HttpMsgSection;

class HttpContextData : public snort::IpsContextData
{
public:
    void clear() override
    { current_section = nullptr; }

    static void init()
    { ips_id = IpsContextData::get_ips_id(); }
    static HttpMsgSection* get_snapshot(const snort::Packet* p);
    static HttpMsgSection* get_snapshot(const snort::Flow* flow,
        snort::IpsContext* context = nullptr);
    static void save_snapshot(HttpMsgSection* section);
    static HttpMsgSection* clear_snapshot(snort::IpsContext* context);
    static unsigned ips_id;

private:
    HttpMsgSection* current_section = nullptr;
};

#endif

