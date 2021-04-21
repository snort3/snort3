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
// http_js_norm.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_js_norm.h"

#include "utils/js_norm_state.h"
#include "utils/js_normalizer.h"
#include "utils/safec.h"
#include "utils/util_jsnorm.h"

#include "http_enum.h"

using namespace HttpEnums;
using namespace snort;

HttpJsNorm::HttpJsNorm(const HttpParaList::UriParam& uri_param_) :
    uri_param(uri_param_), javascript_search_mpse(nullptr),
    htmltype_search_mpse(nullptr)
{}

HttpJsNorm::~HttpJsNorm()
{
    delete javascript_search_mpse;
    delete js_src_attr_search_mpse;
    delete htmltype_search_mpse;
}

void HttpJsNorm::configure()
{
    if ( configure_once )
        return;

    javascript_search_mpse = new SearchTool;
    js_src_attr_search_mpse = new SearchTool;
    htmltype_search_mpse = new SearchTool;

    javascript_search_mpse->add(script_start, script_start_length, JS_JAVASCRIPT);
    javascript_search_mpse->prep();

    js_src_attr_search_mpse->add(script_src_attr, script_src_attr_length, JS_ATTR_SRC);
    js_src_attr_search_mpse->prep();

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

    configure_once = true;
}

void HttpJsNorm::enhanced_normalize(const Field& input, Field& output, HttpInfractions* infractions,
    HttpEventGen* events, int64_t js_normalization_depth) const
{
    bool js_present = false;
    int index = 0;
    const char* ptr = (const char*)input.start();
    const char* const end = ptr + input.length();

    uint8_t* buffer = new uint8_t[input.length()];

    JSNormState state;
    state.norm_depth = js_normalization_depth;
    state.alerts = 0;

    while (ptr < end)
    {
        int bytes_copied = 0;
        int mindex;

        // Search for beginning of a javascript
        if (javascript_search_mpse->find(ptr, end-ptr, search_js_found, false, &mindex) > 0)
        {
            const char* js_start = ptr + mindex;
            const char* const angle_bracket =
                (const char*)SnortStrnStr(js_start, end - js_start, ">");
            if (angle_bracket == nullptr || (end - angle_bracket) == 0)
                break;

            bool type_js = false;
            bool external_js = false;
            if (angle_bracket > js_start)
            {
                int mid;
                const int script_found = htmltype_search_mpse->find(
                    js_start, (angle_bracket-js_start), search_html_found, false, &mid);

                external_js = is_external_script(js_start, angle_bracket);

                js_start = angle_bracket + 1;
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
            }

            ptr = js_start;
            if (!type_js or external_js)
                continue;

            JSNormalizer::normalize(js_start, (uint16_t)(end-js_start), (char*)buffer+index,
                (uint16_t)(input.length() - index), &ptr, &bytes_copied, state);

            HttpModule::increment_peg_counts(PEG_JS_INLINE);

            index += bytes_copied;
        }
        else
            break;
    }

    if (js_present)
    {
        if (state.alerts & ALERT_UNEXPECTED_TAG)
        {
            *infractions += INF_JS_UNEXPECTED_TAG;
            events->create_event(EVENT_JS_UNEXPECTED_TAG);
        }
        output.set(index, buffer, true);
    }
    else
        delete[] buffer;
}

void HttpJsNorm::legacy_normalize(const Field& input, Field& output, HttpInfractions* infractions,
    HttpEventGen* events, int max_javascript_whitespaces) const
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
            const char* const angle_bracket =
                (const char*)SnortStrnStr(js_start, end - js_start, ">");
            if (angle_bracket == nullptr || (end - angle_bracket) == 0)
                break;

            bool type_js = false;
            if (angle_bracket > js_start)
            {
                int mid;
                const int script_found = htmltype_search_mpse->find(
                    js_start, (angle_bracket-js_start), search_html_found, false, &mid);

                js_start = angle_bracket + 1;
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
            memmove_s(buffer + index, input.length() - index, ptr, end - ptr);
            index += end - ptr;
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
int HttpJsNorm::search_js_src_attr_found(void*, void*, int index, void* index_ptr, void*)
{
    *((int*) index_ptr) = index - script_src_attr_length;
    return 1;
}
int HttpJsNorm::search_html_found(void* id, void*, int, void* id_ptr, void*)
{
    *((int*) id_ptr)  = (int)(uintptr_t)id;
    return 1;
}

bool HttpJsNorm::is_external_script(const char* it, const char* script_tag_end) const
{
    int src_pos;

    while (js_src_attr_search_mpse->find(it, (script_tag_end - it),
        search_js_src_attr_found, false, &src_pos))
    {
        it += (src_pos + script_src_attr_length - 1);
        while (++it < script_tag_end)
        {
            if (*it == ' ')
                continue;
            else if (*it == '=')
                return true;
            else
                break;
        }
    }

    return false;
}

