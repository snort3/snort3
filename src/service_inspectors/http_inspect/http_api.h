//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_api.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_API_H
#define HTTP_API_H

#include "framework/inspector.h"
#include "framework/module.h"

#include "http_flow_data.h"
#include "http_module.h"

#define HTTP_CLASSIC_BUFFER_NAMES \
    "file_data",                  \
    "http_client_body",           \
    "http_cookie",                \
    "http_header",                \
    "http_method",                \
    "http_param",                 \
    "http_raw_body",              \
    "http_raw_cookie",            \
    "http_raw_header",            \
    "http_raw_request",           \
    "http_raw_status",            \
    "http_raw_trailer",           \
    "http_raw_uri",               \
    "http_stat_code",             \
    "http_stat_msg",              \
    "http_trailer",               \
    "http_true_ip",               \
    "http_uri",                   \
    "http_version",               \
    "js_data",                    \
    "vba_data"

class HttpApi
{
public:
    static const snort::InspectApi http_api;
    static const char* classic_buffer_names[];

private:
    HttpApi() = delete;
    static snort::Module* http_mod_ctor() { return new HttpModule; }
    static void http_mod_dtor(snort::Module* m) { delete m; }
    static const char* http_my_name;
    static const char* http_help;
    static void http_init();
    static void http_term() { }
    static snort::Inspector* http_ctor(snort::Module* mod);
    static void http_dtor(snort::Inspector* p) { delete p; }
};

#endif

