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

#include "main/snort_debug.h"
#include "utils/js_normalizer.h"
#include "utils/safec.h"
#include "utils/util_jsnorm.h"

#include "http_common.h"
#include "http_enum.h"

using namespace HttpEnums;
using namespace snort;

static const char* jsret_codes[] =
{
    "end of stream",
    "script ended",
    "script continues",
    "opening tag",
    "closing tag",
    "bad token",
    "identifier overflow",
    "template nesting overflow",
    "scope nesting overflow",
    "wrong closing symbol",
    "ended in inner scope",
    "unknown"
};

static const char* ret2str(JSTokenizer::JSRet ret)
{
    assert(ret < JSTokenizer::JSRet::MAX);
    ret = ret < JSTokenizer::JSRet::MAX ? ret : JSTokenizer::JSRet::MAX;
    return jsret_codes[ret];
}

static inline JSTokenizer::JSRet js_normalize(JSNormalizer& ctx, const char* const end,
    const char*& ptr)
{
    trace_logf(3, http_trace, TRACE_JS_DUMP, nullptr,
        "original[%zu]: %.*s\n", end - ptr, static_cast<int>(end - ptr), ptr);

    auto ret = ctx.normalize(ptr, end - ptr);
    auto src_next = ctx.get_src_next();

    trace_logf(3, http_trace, TRACE_JS_PROC, nullptr,
        "normalizer returned with %d '%s'\n", ret, ret2str(ret));

    if (src_next > ptr)
        HttpModule::increment_peg_counts(PEG_JS_BYTES, src_next - ptr);
    else
        src_next = end; // Normalizer has failed, thus aborting the remaining input

    ptr = src_next;

    return ret;
}

HttpJsNorm::HttpJsNorm(const HttpParaList::UriParam& uri_param_, int64_t normalization_depth_,
    int32_t identifier_depth_, uint8_t max_template_nesting_, uint32_t max_scope_depth_,
    const std::unordered_set<std::string>& built_in_ident_) :
    uri_param(uri_param_),
    normalization_depth(normalization_depth_),
    identifier_depth(identifier_depth_),
    max_template_nesting(max_template_nesting_),
    max_scope_depth(max_scope_depth_),
    built_in_ident(built_in_ident_),
    mpse_otag(nullptr),
    mpse_attr(nullptr),
    mpse_type(nullptr)
{}

HttpJsNorm::~HttpJsNorm()
{
    delete mpse_otag;
    delete mpse_attr;
    delete mpse_type;
}

void HttpJsNorm::configure()
{
    if (configure_once)
        return;

    mpse_otag = new SearchTool;
    mpse_attr = new SearchTool;
    mpse_type = new SearchTool;

    static constexpr const char* otag_start = "<SCRIPT";
    static constexpr const char* attr_slash = "/";
    static constexpr const char* attr_gt = ">";
    static constexpr const char* attr_src = "SRC";
    static constexpr const char* attr_js1 = "JAVASCRIPT";
    static constexpr const char* attr_js2 = "ECMASCRIPT";
    static constexpr const char* attr_vb = "VBSCRIPT";

    mpse_otag->add(otag_start, strlen(otag_start), 0);
    mpse_attr->add(attr_slash, strlen(attr_slash), AID_SLASH);
    mpse_attr->add(attr_gt, strlen(attr_gt), AID_GT);
    mpse_attr->add(attr_src, strlen(attr_src), AID_SRC);
    mpse_attr->add(attr_js1, strlen(attr_js1), AID_JS);
    mpse_attr->add(attr_js2, strlen(attr_js2), AID_ECMA);
    mpse_attr->add(attr_vb, strlen(attr_vb), AID_VB);
    mpse_type->add(attr_js1, strlen(attr_js1), AID_JS);
    mpse_type->add(attr_js2, strlen(attr_js2), AID_ECMA);
    mpse_type->add(attr_vb, strlen(attr_vb), AID_VB);

    mpse_otag->prep();
    mpse_attr->prep();
    mpse_type->prep();

    configure_once = true;
}

void HttpJsNorm::enhanced_external_normalize(const Field& input,
    HttpInfractions* infractions, HttpFlowData* ssn, char*& out_buf, size_t& out_len) const
{
    if (ssn->js_built_in_event)
        return;

    const char* ptr = (const char*)input.start();
    const char* const end = ptr + input.length();

    HttpEventGen* events = ssn->events[HttpCommon::SRC_SERVER];

    if (!alive_ctx(ssn))
    {
        HttpModule::increment_peg_counts(PEG_JS_EXTERNAL);
        trace_logf(2, http_trace, TRACE_JS_PROC, nullptr,
            "script starts\n");
    }
    else
        trace_logf(2, http_trace, TRACE_JS_PROC, nullptr,
            "script continues\n");


    auto& js_ctx = ssn->acquire_js_ctx(identifier_depth, normalization_depth, max_template_nesting,
        max_scope_depth, built_in_ident);

    while (ptr < end)
    {
        trace_logf(1, http_trace, TRACE_JS_PROC, nullptr,
            "external script at %zd offset\n", ptr - (const char*)input.start());

        auto ret = js_normalize(js_ctx, end, ptr);

        switch (ret)
        {
        case JSTokenizer::EOS:
        case JSTokenizer::SCRIPT_CONTINUE:
            break;
        case JSTokenizer::SCRIPT_ENDED:
        case JSTokenizer::CLOSING_TAG:
            *infractions += INF_JS_CLOSING_TAG;
            events->create_event(EVENT_JS_CLOSING_TAG);
            ssn->js_built_in_event = true;
            break;
        case JSTokenizer::OPENING_TAG:
            *infractions += INF_JS_OPENING_TAG;
            events->create_event(EVENT_JS_OPENING_TAG);
            ssn->js_built_in_event = true;
            break;
        case JSTokenizer::BAD_TOKEN:
        case JSTokenizer::WRONG_CLOSING_SYMBOL:
        case JSTokenizer::ENDED_IN_INNER_SCOPE:
            *infractions += INF_JS_BAD_TOKEN;
            events->create_event(EVENT_JS_BAD_TOKEN);
            ssn->js_built_in_event = true;
            break;
        case JSTokenizer::IDENTIFIER_OVERFLOW:
            HttpModule::increment_peg_counts(PEG_JS_IDENTIFIER_OVERFLOW);
            *infractions += INF_JS_IDENTIFIER_OVERFLOW;
            events->create_event(EVENT_JS_IDENTIFIER_OVERFLOW);
            ssn->js_built_in_event = true;
            break;
        case JSTokenizer::TEMPLATE_NESTING_OVERFLOW:
        case JSTokenizer::SCOPE_NESTING_OVERFLOW:
            *infractions += INF_JS_SCOPE_NEST_OVFLOW;
            events->create_event(EVENT_JS_SCOPE_NEST_OVFLOW);
            ssn->js_built_in_event = true;
            break;
        default:
            assert(false);
            break;
        }

        if (ssn->js_built_in_event)
            break;
    }

    auto result = js_ctx.get_script();
    out_buf = result.first;

    if (out_buf)
    {
        out_len = result.second;

        trace_logf(1, http_trace, TRACE_JS_DUMP, nullptr,
            "js_data[%zu]: %.*s\n", out_len, static_cast<int>(out_len), out_buf);
    }
}

void HttpJsNorm::enhanced_inline_normalize(const Field& input,
    HttpInfractions* infractions, HttpFlowData* ssn, char*& out_buf, size_t& out_len) const
{
    const char* ptr = (const char*)input.start();
    const char* const end = ptr + input.length();

    HttpEventGen* events = ssn->events[HttpCommon::SRC_SERVER];

    bool script_continue = alive_ctx(ssn);
    bool script_external = false;

    while (ptr < end)
    {
        if (!script_continue)
        {
            if (!mpse_otag->find(ptr, end - ptr, match_otag, false, &ptr))
                break;
            if (ptr >= end)
                break;

            MatchContext sctx = {ptr, true, false, false};

            if (ptr[0] == '>')
                ptr++;
            else
            {
                if (!mpse_attr->find(ptr, end - ptr, match_attr, false, &sctx))
                    break; // the opening tag never ends
                ptr = sctx.next;
            }

            trace_logf(1, http_trace, TRACE_JS_PROC, nullptr,
                "opening tag at %zd offset\n", ptr - (const char*)input.start());

            trace_logf(2, http_trace, TRACE_JS_PROC, nullptr,
                "script attributes [%s, %s, %s]\n",
                sctx.is_shortened ? "shortened form" : "full form",
                sctx.is_javascript ? "JavaScript type" : "unknown type",
                sctx.is_external ? "external source" : "inline");

            if (sctx.is_shortened)
            {
                *infractions += INF_JS_SHORTENED_TAG;
                events->create_event(EVENT_JS_SHORTENED_TAG);
                continue;
            }

            if (!sctx.is_javascript)
                continue;

            script_external = sctx.is_external;

            // script found
            if (!script_external)
                HttpModule::increment_peg_counts(PEG_JS_INLINE);
        }

        auto& js_ctx = ssn->acquire_js_ctx(identifier_depth, normalization_depth,
            max_template_nesting, max_scope_depth, built_in_ident);
        auto output_size_before = js_ctx.peek_script_size();

        auto ret = js_normalize(js_ctx, end, ptr);

        switch (ret)
        {
        case JSTokenizer::EOS:
            js_ctx.reset_depth();
            break;
        case JSTokenizer::SCRIPT_ENDED:
            break;
        case JSTokenizer::SCRIPT_CONTINUE:
            break;
        case JSTokenizer::OPENING_TAG:
            *infractions += INF_JS_OPENING_TAG;
            events->create_event(EVENT_JS_OPENING_TAG);
            break;
        case JSTokenizer::CLOSING_TAG:
            *infractions += INF_JS_CLOSING_TAG;
            events->create_event(EVENT_JS_CLOSING_TAG);
            break;
        case JSTokenizer::BAD_TOKEN:
        case JSTokenizer::WRONG_CLOSING_SYMBOL:
        case JSTokenizer::ENDED_IN_INNER_SCOPE:
            *infractions += INF_JS_BAD_TOKEN;
            events->create_event(EVENT_JS_BAD_TOKEN);
            break;
        case JSTokenizer::IDENTIFIER_OVERFLOW:
            HttpModule::increment_peg_counts(PEG_JS_IDENTIFIER_OVERFLOW);
            *infractions += INF_JS_IDENTIFIER_OVERFLOW;
            events->create_event(EVENT_JS_IDENTIFIER_OVERFLOW);
            break;
        case JSTokenizer::TEMPLATE_NESTING_OVERFLOW:
        case JSTokenizer::SCOPE_NESTING_OVERFLOW:
            *infractions += INF_JS_SCOPE_NEST_OVFLOW;
            events->create_event(EVENT_JS_SCOPE_NEST_OVFLOW);
            break;
        default:
            assert(false);
            break;
        }

        if (script_external && output_size_before != js_ctx.peek_script_size())
        {
            *infractions += INF_JS_CODE_IN_EXTERNAL;
            events->create_event(EVENT_JS_CODE_IN_EXTERNAL);
        }

        script_continue = ret == JSTokenizer::SCRIPT_CONTINUE;
    }

    if (!alive_ctx(ssn))
        return;

    auto js_ctx = ssn->js_normalizer;
    auto result = js_ctx->get_script();
    out_buf = result.first;

    if (out_buf)
    {
        out_len = result.second;

        trace_logf(1, http_trace, TRACE_JS_DUMP, nullptr,
            "js_data[%zu]: %.*s\n", out_len, static_cast<int>(out_len), out_buf);
    }

    if (!script_continue)
        ssn->release_js_ctx();
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
        if (mpse_otag->find(ptr, end-ptr, search_js_found, false, &mindex) > 0)
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
                    js_start, (angle_bracket-js_start), search_html_found, false, &mid);

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

int HttpJsNorm::search_js_found(void*, void*, int index, void* index_ptr, void*)
{
    static constexpr int script_start_length = sizeof("<SCRIPT") - 1;
    *((int*) index_ptr) = index - script_start_length;
    return 1;
}

int HttpJsNorm::search_html_found(void* id, void*, int, void* id_ptr, void*)
{
    *((int*) id_ptr)  = (int)(uintptr_t)id;
    return 1;
}

int HttpJsNorm::match_otag(void*, void*, int index, void* ptr, void*)
{
    *(char**)ptr += index;
    return 1;
}

int HttpJsNorm::match_attr(void* pid, void*, int index, void* sctx, void*)
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
        c = ctx->next + index;
        while (*c == ' ') c++;
        ctx->is_external = ctx->is_external || *c == '=';
        return 0;

    case AID_JS:
        ctx->is_javascript = true;
        return 0;

    case AID_ECMA:
        ctx->is_javascript = true;
        return 0;

    case AID_VB:
        ctx->is_javascript = false;
        return 0;

    default:
        ctx->is_external = false;
        ctx->is_javascript = false;
        ctx->next += index;
        return 1;
    }
}
