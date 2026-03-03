//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector_module.h author Maya Dagon <mdagon@cisco.com>

#ifndef PAYLOAD_INJECTOR_MODULE_H
#define PAYLOAD_INJECTOR_MODULE_H

#include "framework/module.h"

struct PayloadInjectorCounts
{
    PegCount http_injects;
    PegCount http2_injects;
    PegCount failed_injects;
    PegCount http2_translate_err;
    PegCount http2_mid_frame;
    PegCount err_unidentified_protocol;
    PegCount err_stream_not_established;
    PegCount err_injector_not_configured;
    PegCount err_conflicting_s2c_traffic;
    PegCount err_http2_even_stream;
    PegCount err_http2_stream_id_0;
    PegCount err_session_not_tcp;
    PegCount err_stale_s2c_data;
    PegCount err_s2c_http_proto;
    PegCount err_c2s_http_proto;
    PegCount err_s2c_http2_proto;
};

extern THREAD_LOCAL PayloadInjectorCounts payload_injector_stats;

class SO_PUBLIC PayloadInjectorModule : public snort::Module
{
public:
    PayloadInjectorModule();
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return GLOBAL; }

    bool end(const char*, int, snort::SnortConfig*) override;
};

#endif

