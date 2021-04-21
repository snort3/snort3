//--------------------------------------------------------------------------
// Copyright (C) 2016-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "http_event.h"
#include "http_module.h"

//-------------------------------------------------------------------------
// HttpJsNorm class
//-------------------------------------------------------------------------

class HttpJsNorm
{
public:
    HttpJsNorm(const HttpParaList::UriParam& uri_param_);
    ~HttpJsNorm();
    void legacy_normalize(const Field& input, Field& output, HttpInfractions* infractions,
        HttpEventGen* events, int max_javascript_whitespaces) const;
    void enhanced_normalize(const Field& input, Field& output, HttpInfractions* infractions,
        HttpEventGen* events, int64_t js_normalization_depth) const;

    void configure();
private:
    bool configure_once = false;

    enum JsSearchId { JS_JAVASCRIPT };
    enum JsSrcAttrSearchId { JS_ATTR_SRC };
    enum HtmlSearchId { HTML_JS, HTML_EMA, HTML_VB };

    static constexpr const char* script_start = "<SCRIPT";
    static constexpr int script_start_length = sizeof("<SCRIPT") - 1;
    static constexpr const char* script_src_attr = "SRC";
    static constexpr int script_src_attr_length = sizeof("SRC") - 1;

    const HttpParaList::UriParam& uri_param;

    snort::SearchTool* javascript_search_mpse;
    snort::SearchTool* js_src_attr_search_mpse;
    snort::SearchTool* htmltype_search_mpse;

    static int search_js_found(void*, void*, int index, void*, void*);
    static int search_js_src_attr_found(void*, void*, int index, void*, void*);
    static int search_html_found(void* id, void*, int, void*, void*);

    bool is_external_script(const char* it, const char* script_tag_end) const;
};

#endif

