//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_js_norm.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_JS_NORM_H
#define HTTP_JS_NORM_H

#include <cstring>

#include "search_engines/search_tool.h"

#include "http_field.h"
#include "http_event_gen.h"
#include "http_infractions.h"
#include "http_module.h"

//-------------------------------------------------------------------------
// HttpJsNorm class
//-------------------------------------------------------------------------

class HttpJsNorm
{
public:
    HttpJsNorm(int max_javascript_whitespaces_, const HttpParaList::UriParam& uri_param_);
    ~HttpJsNorm();
    void normalize(const Field& input, Field& output, HttpInfractions* infractions,
        HttpEventGen* events) const;
    void configure();
private:
    enum JsSearchId { JS_JAVASCRIPT };
    enum HtmlSearchId { HTML_JS, HTML_EMA, HTML_VB };

    static constexpr const char* script_start = "<SCRIPT";
    static constexpr int script_start_length = sizeof("<SCRIPT") - 1;

    const int max_javascript_whitespaces;
    const HttpParaList::UriParam& uri_param;

    snort::SearchTool* javascript_search_mpse;
    snort::SearchTool* htmltype_search_mpse;

    static int search_js_found(void*, void*, int index, void*, void*);
    static int search_html_found(void* id, void*, int, void*, void*);
};

#endif

