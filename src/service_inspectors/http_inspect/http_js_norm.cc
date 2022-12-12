//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
// http_js_norm.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_js_norm.h"

#include "js_norm/js_enum.h"
#include "js_norm/js_normalizer.h"
#include "trace/trace_api.h"
#include "utils/safec.h"
#include "utils/util_jsnorm.h"

using namespace HttpEnums;
using namespace jsn;
using namespace snort;

extern THREAD_LOCAL const snort::Trace* js_trace;

enum AttrId { AID_OPEN, AID_SLASH, AID_GT, AID_SRC, AID_JS, AID_NON_JS, AID_ECMA, AID_VB };

struct MatchContext
{
    const uint8_t* next = nullptr;
    bool is_javascript = true;
    bool is_external = false;
    bool is_shortened = false;
};

SearchTool* js_create_mpse_open_tag()
{
    constexpr const char* otag_start = "<SCRIPT";
    SearchTool* mpse = new SearchTool;

    mpse->add(otag_start, strlen(otag_start), AID_OPEN);

    mpse->prep();

    return mpse;
}

SearchTool* js_create_mpse_tag_type()
{
    constexpr const char* attr_js = "JAVASCRIPT";
    constexpr const char* attr_ecma = "ECMASCRIPT";
    constexpr const char* attr_vb = "VBSCRIPT";
    SearchTool* mpse = new SearchTool;

    mpse->add(attr_js, strlen(attr_js), AID_JS);
    mpse->add(attr_ecma, strlen(attr_ecma), AID_ECMA);
    mpse->add(attr_vb, strlen(attr_vb), AID_VB);

    mpse->prep();

    return mpse;
}

SearchTool* js_create_mpse_tag_attr()
{
    constexpr const char* attr_slash = "/";
    constexpr const char* attr_gt = ">";
    constexpr const char* attr_src = "SRC";

    constexpr const char* attrs_js[] =
    {
        "APPLICATION/JAVASCRIPT",
        "APPLICATION/ECMASCRIPT",
        "APPLICATION/X-JAVASCRIPT",
        "APPLICATION/X-ECMASCRIPT",
        "TEXT/JAVASCRIPT",
        "TEXT/JAVASCRIPT1.0",
        "TEXT/JAVASCRIPT1.1",
        "TEXT/JAVASCRIPT1.2",
        "TEXT/JAVASCRIPT1.3",
        "TEXT/JAVASCRIPT1.4",
        "TEXT/JAVASCRIPT1.5",
        "TEXT/ECMASCRIPT",
        "TEXT/X-JAVASCRIPT",
        "TEXT/X-ECMASCRIPT",
        "TEXT/JSCRIPT"
    };
    constexpr const size_t attrs_js_size = sizeof(attrs_js) / sizeof(attrs_js[0]);

    constexpr const char* attrs_non_js[] =
    {
        "TEXT/VBSCRIPT",
        "APPLICATION/JSON"
    };
    constexpr const size_t attrs_non_js_size = sizeof(attrs_non_js) / sizeof(attrs_non_js[0]);

    SearchTool* mpse = new SearchTool;

    mpse->add(attr_slash, strlen(attr_slash), AID_SLASH);
    mpse->add(attr_gt, strlen(attr_gt), AID_GT);
    mpse->add(attr_src, strlen(attr_src), AID_SRC);

    for (unsigned i = 0; i < attrs_js_size; ++i)
        mpse->add(attrs_js[i], strlen(attrs_js[i]), AID_JS);

    for (unsigned i = 0; i < attrs_non_js_size; ++i)
        mpse->add(attrs_non_js[i], strlen(attrs_non_js[i]), AID_NON_JS);

    mpse->prep();

    return mpse;
}

static int match_script(void*, void*, int index, void* index_ptr, void*)
{
    static constexpr int script_start_length = sizeof("<SCRIPT") - 1;
    *((int*) index_ptr) = index - script_start_length;
    return 1;
}

static int match_html(void* id, void*, int, void* id_ptr, void*)
{
    *((int*) id_ptr)  = (int)(uintptr_t)id;
    return 1;
}

static int match_otag(void*, void*, int index, void* ptr, void*)
{
    *(uint8_t**)ptr += index;
    return 1;
}

static int match_attr(void* pid, void*, int index, void* sctx, void*)
{
    MatchContext* ctx = (MatchContext*)sctx;
    AttrId id = (AttrId)(uintptr_t)pid;
    const char* c;

    switch (id)
    {
    case AID_SLASH:
        if (*(ctx->next + index) == '>')
        {
            ctx->is_shortened = true;
            ctx->next += index;
            return 1;
        }
        else
        {
            ctx->is_shortened = false;
            return 0;
        }

    case AID_GT:
        ctx->next += index;
        return 1;

    case AID_SRC:
        c = (const char*)ctx->next + index;
        while (*c == ' ') c++;
        ctx->is_external = ctx->is_external || *c == '=';
        return 0;

    case AID_JS:
        ctx->is_javascript = true;
        return 0;

    case AID_NON_JS:
        ctx->is_javascript = false;
        return 0;

    default:
        assert(false);
        return 1;
    }
}

void js_normalize(const Field& input, Field& output,
    const HttpParaList* params, HttpInfractions* inf, HttpEventGen* events)
{
    assert(params);
    assert(inf);
    assert(events);

    bool js_present = false;
    int index = 0;
    const char* ptr = (const char*)input.start();
    const char* const end = ptr + input.length();
    auto mpse_otag = params->js_norm_param.mpse_otag;
    auto mpse_type = params->js_norm_param.mpse_type;
    auto& uri_param = params->uri_param;

    JSState js;
    js.allowed_spaces = params->js_norm_param.max_javascript_whitespaces;
    js.allowed_levels = MAX_ALLOWED_OBFUSCATION;
    js.alerts = 0;

    uint8_t* buffer = new uint8_t[input.length()];

    while (ptr < end)
    {
        int bytes_copied = 0;
        int mindex;

        // Search for beginning of a javascript
        if (mpse_otag->find(ptr, end-ptr, match_script, false, &mindex) > 0)
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
                const int script_found = mpse_type->find(
                    js_start, (angle_bracket-js_start), match_html, false, &mid);

                js_start = angle_bracket + 1;
                if (script_found > 0)
                {
                    switch (mid)
                    {
                    case AID_JS:
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
                *inf += INF_JS_OBFUSCATION_EXCD;
                events->create_event(EVENT_JS_OBFUSCATION_EXCD);
            }
            if (js.alerts & ALERT_SPACES_EXCEEDED)
            {
                *inf += INF_JS_EXCESS_WS;
                events->create_event(EVENT_JS_EXCESS_WS);
            }
            if (js.alerts & ALERT_MIXED_ENCODINGS)
            {
                *inf += INF_MIXED_ENCODINGS;
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

bool HttpInlineJSNorm::pre_proc()
{
    assert(mpse_otag);
    assert(mpse_attr);
    assert(http_events);
    assert(infractions);

    if (src_ptr >= src_end)
        return false;

    const Packet* packet = DetectionEngine::get_current_packet();

    if (!script_continue)
    {
        while (true)
        {
            if (!mpse_otag->find((const char*)src_ptr, src_end - src_ptr, match_otag, false, &src_ptr)
                || src_ptr >= src_end)
            {
                return false;
            }

            MatchContext sctx = {src_ptr, true, false, false};

            if (!mpse_attr->find((const char*)src_ptr, src_end - src_ptr, match_attr, false, &sctx)
                || src_ptr == sctx.next || sctx.next >= src_end)
            {
                return false;
            }

            src_ptr = sctx.next;

            trace_logf(1, js_trace, TRACE_PROC, packet,
                "opening tag at %zd offset\n", src_ptr - page_start);

            trace_logf(2, js_trace, TRACE_PROC, packet,
                "script attributes [%s, %s, %s]\n",
                sctx.is_shortened ? "shortened form" : "full form",
                sctx.is_javascript ? "JavaScript type" : "unknown type",
                sctx.is_external ? "external source" : "inline");

            if (sctx.is_shortened)
            {
                *infractions += INF_JS_SHORTENED_TAG;
                http_events->create_event(EVENT_JS_SHORTENED_TAG);
                continue;
            }

            if (!sctx.is_javascript)
                continue;

            ext_ref_type = sctx.is_external;

            break;
        }

        if (!ext_ref_type)
            HttpModule::increment_peg_counts(PEG_JS_INLINE);
    }

    ext_script_type = false;
    output_size = jsn_ctx->script_size();

    return true;
}

bool HttpInlineJSNorm::post_proc(int ret)
{
    assert(http_events);
    assert(infractions);

    if (ext_ref_type && output_size != jsn_ctx->script_size())
    {
        *infractions += INF_JS_CODE_IN_EXTERNAL;
        http_events->create_event(EVENT_JS_CODE_IN_EXTERNAL);
    }

    script_continue = ret == (int)jsn::JSTokenizer::SCRIPT_CONTINUE;

    if (!script_continue)
        jsn_ctx->reset_depth();

    JSNorm::post_proc(ret);

    return true; // reuse context
}

bool HttpExternalJSNorm::pre_proc()
{
    if (src_ptr >= src_end)
        return false;

    const Packet* packet = DetectionEngine::get_current_packet();

    if (!ext_script_type)
    {
        HttpModule::increment_peg_counts(PEG_JS_EXTERNAL);
        trace_logf(1, js_trace, TRACE_PROC, packet,
            "external script starts\n");
        ext_script_type = true;
    }
    else
    {
        trace_logf(2, js_trace, TRACE_PROC, packet,
            "script continues\n");
    }

    return true;
}

bool HttpExternalJSNorm::post_proc(int ret)
{
    script_continue = ret == (int)jsn::JSTokenizer::SCRIPT_CONTINUE;

    return JSNorm::post_proc(ret);
}

bool HttpPDFJSNorm::pre_proc()
{
    if (src_ptr >= src_end)
        return false;

    if (!ext_script_type)
        HttpModule::increment_peg_counts(PEG_JS_PDF);

    return PDFJSNorm::pre_proc();
}

bool HttpPDFJSNorm::post_proc(int ret)
{
    script_continue = ret == (int)jsn::JSTokenizer::SCRIPT_CONTINUE;

    return PDFJSNorm::post_proc(ret);
}
