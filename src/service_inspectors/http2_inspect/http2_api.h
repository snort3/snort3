//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// http2_api.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_API_H
#define HTTP2_API_H

#include "framework/inspector.h"
#include "framework/module.h"

#include "http2_flow_data.h"
#include "http2_module.h"

class Http2Api
{
public:
    static const snort::InspectApi http2_api;
    static const char* classic_buffer_names[];

private:
    Http2Api() = delete;
    static snort::Module* http2_mod_ctor() { return new Http2Module; }
    static void http2_mod_dtor(snort::Module* m) { delete m; }
    static const char* http2_my_name;
    static const char* http2_help;
    static void http2_init() { Http2FlowData::init(); }
    static void http2_term() { }
    static snort::Inspector* http2_ctor(snort::Module* mod);
    static void http2_dtor(snort::Inspector* p) { delete p; }
};

#endif

