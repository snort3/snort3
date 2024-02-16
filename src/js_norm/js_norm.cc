//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// js_norm.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_norm.h"

#include "log/messages.h"
#include "trace/trace_api.h"

#include "js_identifier_ctx.h"
#include "js_normalizer.h"
#include "js_norm_module.h"

using namespace jsn;
using namespace snort;

static const char* jsret_codes[] =
{
    "end of stream",
    "script ended",
    "script continues",
    "closing tag",
    "bad token",
    "identifier overflow",
    "template nesting overflow",
    "bracket nesting overflow",
    "scope nesting overflow",
    "wrong closing symbol",
    "ended in inner scope",
    "unknown"
};

const char* jsn::ret2str(int r)
{
    JSTokenizer::JSRet ret = (JSTokenizer::JSRet)r;

    assert(ret < JSTokenizer::JSRet::MAX);
    assert(ret < sizeof(jsret_codes)/sizeof(jsret_codes[0]));

    ret = ret < JSTokenizer::JSRet::MAX ? ret : JSTokenizer::JSRet::MAX;

    return jsret_codes[ret];
}

JSNorm::JSNorm(JSNormConfig* jsn_config, bool ext_script_type, uint32_t generation_id) :
    alive(true), pdu_cnt(0), src_ptr(nullptr), src_end(nullptr), idn_ctx(nullptr),
    jsn_ctx(nullptr), ext_script_type(ext_script_type), generation_id(generation_id)
{
    config = jsn_config;
    alive = (bool)config;

    if (!alive)
        return;
    debug_log(4, js_trace, TRACE_PROC, nullptr, "context created\n");
}

JSNorm::~JSNorm()
{
    delete idn_ctx;
    delete jsn_ctx;

    debug_log(4, js_trace, TRACE_PROC, nullptr, "context deleted\n");
}

void JSNorm::normalize(const void* in_data, size_t in_len, const void*& data, size_t& len)
{
    if (!alive)
    {
        len = 0;
        data = nullptr;
        return;
    }

    if (pdu_cnt > 2)
    {
        len = 0;
        data = nullptr;
        return;
    }
    if (pdu_cnt > 1)
    {
        events.create_event(EVENT_DATA_LOST);
        ++pdu_cnt;
        len = 0;
        data = nullptr;
        return;
    }
    pdu_cnt = 0;

    const Packet* packet = DetectionEngine::get_current_packet();
    src_ptr = (const uint8_t*)in_data;
    src_end = src_ptr + in_len;

    while (alive and pre_proc())
    {
        if (idn_ctx == nullptr)
            idn_ctx = new JSIdentifierCtx(config->identifier_depth,
                config->max_scope_depth, config->ignored_ids, config->ignored_props);
        if (jsn_ctx == nullptr)
            jsn_ctx = new JSNormalizer(*idn_ctx, config->bytes_depth,
                config->max_template_nesting, config->max_bracket_depth);
        trace_logf(3, js_trace, TRACE_DUMP, packet,
            "original[%zu]: %.*s\n", src_end - src_ptr, (int)(src_end - src_ptr), src_ptr);

        auto ret = jsn_ctx->normalize((const char*)src_ptr, src_end - src_ptr, ext_script_type);
        const uint8_t* next = (const uint8_t*)jsn_ctx->get_src_next();

        trace_logf(3, js_trace, TRACE_PROC, packet,
            "normalizer returned with %d '%s'\n", ret, jsn::ret2str(ret));

        JSNormModule::increment_peg_counts(PEG_BYTES, next - src_ptr);
        src_ptr = next;

        alive = post_proc(ret);
    }

    if (jsn_ctx != nullptr)
    {
        len = jsn_ctx->script_size();
        data = jsn_ctx->get_script();
    }
    if (data and len)
        trace_logf(1, js_trace, TRACE_DUMP, packet,
            "js_data[%u]: %.*s\n", (unsigned)len, (int)len, (const char*)data);
}

void JSNorm::flush_data(const void*& data, size_t& len)
{
    if (jsn_ctx != nullptr)
    {
        len = jsn_ctx->script_size();
        data = jsn_ctx->take_script();
    }
}

void JSNorm::flush_data()
{
    if (jsn_ctx != nullptr)
    {
        delete[] jsn_ctx->take_script();
    }
}

void JSNorm::get_data(const void*& data, size_t& len)
{
    if (jsn_ctx != nullptr)
    {
        len = jsn_ctx->script_size();
        data = jsn_ctx->get_script();
    }
}

bool JSNorm::pre_proc()
{
    return src_ptr < src_end;
}

bool JSNorm::post_proc(int ret)
{
    if (jsn_ctx->is_unescape_nesting_seen())
        events.create_event(EVENT_NEST_UNESCAPE_FUNC);

    if (jsn_ctx->is_mixed_encoding_seen())
        events.create_event(EVENT_MIXED_UNESCAPE_SEQUENCE);

    if (jsn_ctx->is_opening_tag_seen())
        events.create_event(EVENT_OPENING_TAG);

    if (jsn_ctx->is_closing_tag_seen())
        events.create_event(EVENT_CLOSING_TAG);

    switch ((JSTokenizer::JSRet)ret)
    {
    case JSTokenizer::EOS:
    case JSTokenizer::SCRIPT_ENDED:
    case JSTokenizer::SCRIPT_CONTINUE:
        return true;

    case JSTokenizer::CLOSING_TAG:
        events.create_event(EVENT_CLOSING_TAG);
        return false;

    case JSTokenizer::BAD_TOKEN:
    case JSTokenizer::WRONG_CLOSING_SYMBOL:
    case JSTokenizer::ENDED_IN_INNER_SCOPE:
        events.create_event(EVENT_BAD_TOKEN);
        return false;

    case JSTokenizer::IDENTIFIER_OVERFLOW:
        JSNormModule::increment_peg_counts(PEG_IDENTIFIER_OVERFLOWS);
        events.create_event(EVENT_IDENTIFIER_OVERFLOW);
        return false;

    case JSTokenizer::TEMPLATE_NESTING_OVERFLOW:
    case JSTokenizer::BRACKET_NESTING_OVERFLOW:
        events.create_event(EVENT_BRACKET_NEST_OVERFLOW);
        return false;

    case JSTokenizer::SCOPE_NESTING_OVERFLOW:
        events.create_event(EVENT_SCOPE_NEST_OVERFLOW);
        return false;

    default:
        assert(false);
        return false;
    }
}
