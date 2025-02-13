//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector.h author Maya Dagon <mdagon@cisco.com>

#ifndef PAYLOAD_INJECTOR_H
#define PAYLOAD_INJECTOR_H

#include "framework/codec.h"

namespace snort
{
struct Packet;
}

enum InjectionReturnStatus : int8_t
{
    INJECTION_SUCCESS = 1,
    ERR_INJECTOR_NOT_CONFIGURED = -1,
    ERR_STREAM_NOT_ESTABLISHED = -2,
    ERR_UNIDENTIFIED_PROTOCOL = -3,
    ERR_HTTP2_STREAM_ID_0 = -4,
    ERR_PAGE_TRANSLATION = -5,
    ERR_HTTP2_MID_FRAME = -6,
    ERR_TRANSLATED_HDRS_SIZE = -7,
    ERR_HTTP2_EVEN_STREAM_ID = -8,
    ERR_PKT_FROM_SERVER = -9,
    ERR_CONFLICTING_S2C_TRAFFIC = -10,
    // Update InjectionErrorToString when adding/removing error codes
};

struct InjectionControl
{
    const uint8_t* http_page = nullptr;
    uint32_t http_page_len = 0;
    int64_t stream_id = 0;
};

class SO_PUBLIC PayloadInjector
{
public:
    static InjectionReturnStatus inject_http_payload(snort::Packet* p, const
        InjectionControl& control);

    static const char* get_err_string(InjectionReturnStatus status);

private:
    static InjectionReturnStatus inject_http2_payload(snort::Packet* p, const
        InjectionControl& control, snort::EncodeFlags df);

#ifdef UNIT_TEST

public:
#endif
    static InjectionReturnStatus get_http2_payload(InjectionControl control,
        uint8_t*& http2_payload, uint32_t& payload_len, bool send_settings);
};

#ifdef UNIT_TEST
InjectionReturnStatus write_7_bit_prefix_int(uint32_t val, uint8_t*& out,
    uint32_t& out_free_space);
#endif

#endif

