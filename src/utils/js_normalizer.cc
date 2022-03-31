//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// js_normalizer.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_normalizer.h"

#define BUFF_EXP_FACTOR 1.3

using namespace snort;
using namespace std;

JSNormalizer::JSNormalizer(JSIdentifierCtxBase& js_ident_ctx, size_t norm_depth,
    uint8_t max_template_nesting, uint32_t max_bracket_depth, int tmp_cap_size)
    : depth(norm_depth),
      rem_bytes(norm_depth),
      unlim(norm_depth == static_cast<size_t>(-1)),
      src_next(nullptr),
      tmp_buf(nullptr),
      tmp_buf_size(0),
      in(&in_buf),
      out(&out_buf),
      tokenizer(in, out, js_ident_ctx, max_template_nesting, max_bracket_depth, tmp_buf, tmp_buf_size, tmp_cap_size)
{
}

JSNormalizer::~JSNormalizer()
{
    delete[] tmp_buf;
    tmp_buf = nullptr;
    tmp_buf_size = 0;
}

JSTokenizer::JSRet JSNormalizer::normalize(const char* src, size_t src_len, bool external_script)
{
    assert(src);

    if (src_len == 0)
    {
        src_next = src;
        return JSTokenizer::SCRIPT_CONTINUE;
    }

    rem_bytes = unlim ? src_len + 1 : rem_bytes;

    if (rem_bytes == 0)
    {
        debug_log(5, http_trace, TRACE_JS_PROC, nullptr,
            "depth limit reached\n");

        src_next = src + src_len;
        return JSTokenizer::EOS;
    }

    debug_logf(4, http_trace, TRACE_JS_DUMP, nullptr,
        "tmp buffer[%zu]: %.*s\n", tmp_buf_size, static_cast<int>(tmp_buf_size), tmp_buf);

    src_len = min(src_len, rem_bytes);

    in_buf.pubsetbuf(nullptr, 0)
        ->pubsetbuf(tmp_buf, tmp_buf_size)
        ->pubsetbuf(const_cast<char*>(src), src_len);
    out_buf.reserve(src_len * BUFF_EXP_FACTOR);

    size_t r_bytes = in_buf.last_chunk_offset();
    auto ret = tokenizer.process(r_bytes, external_script);

    rem_bytes -= r_bytes;
    src_next = src + r_bytes;

    return rem_bytes ? ret : JSTokenizer::EOS;
}
