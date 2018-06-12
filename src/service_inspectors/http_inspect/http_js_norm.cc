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
// http_js_norm.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_js_norm.h"

#include "utils/util_jsnorm.h"
#include "utils/safec.h"

using namespace HttpEnums;
using namespace snort;

HttpJsNorm::HttpJsNorm(int max_javascript_whitespaces_, const HttpParaList::UriParam& uri_param_) :
    max_javascript_whitespaces(max_javascript_whitespaces_), uri_param(uri_param_),
    javascript_search_mpse(nullptr), htmltype_search_mpse(nullptr) {}

HttpJsNorm::~HttpJsNorm()
{
    delete javascript_search_mpse;
    delete htmltype_search_mpse;
}

void HttpJsNorm::configure()
{
    if ( javascript_search_mpse || htmltype_search_mpse )
        return;

    javascript_search_mpse = new snort::SearchTool;
    htmltype_search_mpse = new snort::SearchTool;

    javascript_search_mpse->add(script_start, script_start_length, JS_JAVASCRIPT);
    javascript_search_mpse->prep();

    struct HiSearchToken
    {
        const char* name;
        int name_len;
        int search_id;
    };

    const HiSearchToken html_patterns[] =
    {
        { "JAVASCRIPT",      10, HTML_JS },
        { "ECMASCRIPT",      10, HTML_EMA },
        { "VBSCRIPT",         8, HTML_VB },
        { nullptr,            0, 0 }
    };

    for (const HiSearchToken* tmp = &html_patterns[0]; tmp->name != nullptr; tmp++)
    {
        htmltype_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    htmltype_search_mpse->prep();
}

void HttpJsNorm::normalize(const Field& input, Field& output, HttpInfractions* infractions,
    HttpEventGen* events) const
{
    bool js_present = false;
    int index = 0;
    const char* ptr = (const char*)input.start();
    const char* const end = ptr + input.length();

    JSState js;
    js.allowed_spaces = max_javascript_whitespaces;
    js.allowed_levels = MAX_ALLOWED_OBFUSCATION;
    js.alerts = 0;

    uint8_t* buffer = new uint8_t[input.length()];

    while (ptr < end)
    {
        int bytes_copied = 0;
        int mindex;

        // Search for beginning of a javascript
        if (javascript_search_mpse->find(ptr, end-ptr, search_js_found, false, &mindex) > 0)
        {
            const char* js_start = ptr + mindex;
            const char* const angle_bracket = (const char*)SnortStrnStr(js_start, end - js_start, ">");
            if (angle_bracket == nullptr)
                break;

            bool type_js = false;
            if (angle_bracket > js_start)
            {
                int mid;
                const int script_found = htmltype_search_mpse->find(
                    js_start, (angle_bracket-js_start), search_html_found, false, &mid);

                js_start = angle_bracket;
                if (script_found > 0)
                {
                    switch (mid)
                    {
                    case HTML_JS:
                        js_present = true;
                        type_js = true;
                        break;
                    default:
                        type_js = false;
                        break;
                    }
                }
                else
                {
                    // if no type or language is found we assume it is a javascript
                    js_present = true;
                    type_js = true;
                }
            }
            // Save before the <script> begins
            if (js_start > ptr)
            {
                if ((js_start - ptr) > (input.length() - index))
                    break;
                memmove_s(buffer + index, input.length() - index, ptr, js_start - ptr);
                index += js_start - ptr;
            }

            ptr = js_start;
            if (!type_js)
                continue;

            // FIXIT-L need to fix this library so we don't have to cast away const here.
            JSNormalizeDecode(js_start, (uint16_t)(end-js_start), (char*)buffer+index,
                (uint16_t)(input.length() - index), &ptr, &bytes_copied, &js,
                uri_param.iis_unicode ? uri_param.unicode_map : nullptr);
            index += bytes_copied;
        }
        else
            break;
    }

    if (js_present)
    {
        if ((ptr < end) && ((input.length() - index) >= (end - ptr)))
        {
            memmove_s(buffer + index, input.length() - index, ptr, end - ptr); index += end - ptr;
        }
        if (js.alerts)
        {
            if (js.alerts & ALERT_LEVELS_EXCEEDED)
            {
                *infractions += INF_JS_OBFUSCATION_EXCD;
                events->create_event(EVENT_JS_OBFUSCATION_EXCD);
            }
            if (js.alerts & ALERT_SPACES_EXCEEDED)
            {
                *infractions += INF_JS_EXCESS_WS;
                events->create_event(EVENT_JS_EXCESS_WS);
            }
            if (js.alerts & ALERT_MIXED_ENCODINGS)
            {
                *infractions += INF_MIXED_ENCODINGS;
                events->create_event(EVENT_MIXED_ENCODINGS);
            }
        }
        output.set(index, buffer, true);
    }
    else
    {
        delete[] buffer;
        output.set(input);
    }
}

/* Returning non-zero stops search, which is okay since we only look for one at a time */
int HttpJsNorm::search_js_found(void*, void*, int index, void* index_ptr, void*)
{
    *((int*) index_ptr) = index - script_start_length;
    return 1;
}
int HttpJsNorm::search_html_found(void* id, void*, int, void* id_ptr, void*)
{
    *((int*) id_ptr)  = (int)(uintptr_t)id;
    return 1;
}

