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
#include "http_flow_data.h"
#include "http_event.h"
#include "http_module.h"

//-------------------------------------------------------------------------
// HttpJsNorm class
//-------------------------------------------------------------------------

class HttpJsNorm
{
public:
    HttpJsNorm(const HttpParaList::UriParam&, int64_t normalization_depth,
        int32_t identifier_depth, uint8_t max_template_nesting, uint32_t max_bracket_depth,
        uint32_t max_scope_depth, const std::unordered_set<std::string>& ignored_ids);
    ~HttpJsNorm();

    void set_detection_depth(size_t depth)
    { detection_depth = depth; }

    void do_legacy(const Field& input, Field& output, HttpInfractions*, HttpEventGen*,
        int max_javascript_whitespaces) const;
    void do_inline(const Field& input, Field& output, HttpInfractions*, HttpFlowData*, bool) const;
    void do_external(const Field& input, Field& output, HttpInfractions*, HttpFlowData*, bool) const;

    void configure();

private:
    enum AttrId { AID_SLASH, AID_GT, AID_SRC, AID_JS, AID_ECMA, AID_VB };

    struct MatchContext
    {
        const char* next;
        bool is_javascript;
        bool is_external;
        bool is_shortened;
    };

    const HttpParaList::UriParam& uri_param;
    size_t detection_depth;
    int64_t normalization_depth;
    int32_t identifier_depth;
    uint8_t max_template_nesting;
    uint32_t max_bracket_depth;
    uint32_t max_scope_depth;
    const std::unordered_set<std::string>& ignored_ids;
    bool configure_once = false;

    snort::SearchTool* mpse_otag;
    snort::SearchTool* mpse_attr;
    snort::SearchTool* mpse_type; // legacy only

    static int search_js_found(void*, void*, int index, void*, void*);  // legacy only
    static int search_html_found(void* id, void*, int, void*, void*); // legacy only
    static int match_otag(void*, void*, int, void*, void*);
    static int match_attr(void*, void*, int, void*, void*);

    bool alive_ctx(const HttpFlowData* ssn) const
    { return ssn->js_normalizer; }
};

#endif

