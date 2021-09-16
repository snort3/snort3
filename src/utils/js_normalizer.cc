//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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

using namespace snort;
using namespace std;

JSNormalizer::JSNormalizer(JSIdentifierCtxBase& js_ident_ctx, size_t norm_depth,
    uint8_t max_template_nesting, int tmp_cap_size)
    : depth(norm_depth),
      rem_bytes(norm_depth),
      unlim(norm_depth == static_cast<size_t>(-1)),
      src_next(nullptr),
      dst_next(nullptr),
      tmp_buf(nullptr),
      tmp_buf_size(0),
      in(&in_buf),
      out(&out_buf),
      tokenizer(in, out, js_ident_ctx, max_template_nesting, tmp_buf, tmp_buf_size, tmp_cap_size)
{
}

JSNormalizer::~JSNormalizer()
{
    delete[] tmp_buf;
    tmp_buf = nullptr;
    tmp_buf_size = 0;
}

JSTokenizer::JSRet JSNormalizer::normalize(const char* src, size_t src_len, char* dst, size_t dst_len)
{
    if (rem_bytes == 0 && !unlim)
    {
        debug_log(5, http_trace, TRACE_JS_PROC, nullptr,
            "depth limit reached\n");

        src_next = src + src_len;
        dst_next = dst;
        return JSTokenizer::EOS;
    }

    size_t len = unlim ? src_len :
        src_len < rem_bytes ? src_len : rem_bytes;

    debug_logf(4, http_trace, TRACE_JS_DUMP, nullptr,
        "tmp buffer[%zu]: %.*s\n", tmp_buf_size, static_cast<int>(tmp_buf_size), tmp_buf);

    in_buf.str(tmp_buf, tmp_buf_size, const_cast<char*>(src), len);
    size_t w_bytes = out.tellp();

    JSTokenizer::JSRet ret = static_cast<JSTokenizer::JSRet>(tokenizer.yylex());

    out_buf.sgetn(dst, dst_len);

    in.clear();
    out.clear();
    size_t r_bytes = in_buf.glued() ? static_cast<size_t>(in.tellg()) : 0;
    w_bytes = (size_t)out.tellp() - w_bytes;

    if (!unlim)
        rem_bytes -= r_bytes;
    src_next = src + r_bytes;

    // avoid heap overflow if number of written bytes bigger than accepted dst_len
    dst_next = (w_bytes <= dst_len) ? dst + w_bytes : dst + dst_len;

    return rem_bytes ? ret : JSTokenizer::EOS;
}

size_t JSNormalizer::size()
{
    return sizeof(JSNormalizer) + 16834; // the default YY_BUF_SIZE
}
