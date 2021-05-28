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

JSNormalizer::JSNormalizer()
    : depth(-1),
      rem_bytes(-1),
      unlim(true),
      src_next(nullptr),
      dst_next(nullptr),
      tokenizer(in, out)
{
}

void JSNormalizer::set_depth(size_t new_depth)
{
    if (depth == new_depth)
        return;

    depth = new_depth;
    rem_bytes = depth;
    unlim = depth == (size_t)-1;
}

JSTokenizer::JSRet JSNormalizer::normalize(const char* src, size_t src_len, char* dst, size_t dst_len)
{
    if (rem_bytes == 0 && !unlim)
    {
        src_next = src + src_len;
        dst_next = dst;
        return JSTokenizer::EOS;
    }

    size_t len = unlim ? src_len :
        src_len < rem_bytes ? src_len : rem_bytes;
    in.rdbuf()->pubsetbuf(const_cast<char*>(src), len);
    out.rdbuf()->pubsetbuf(dst, dst_len);

    JSTokenizer::JSRet ret = (JSTokenizer::JSRet)tokenizer.yylex();
    in.clear();
    out.clear();
    size_t r_bytes = in.tellg();
    size_t w_bytes = out.tellp();

    if (!unlim)
        rem_bytes -= r_bytes;
    src_next = src + r_bytes;
    dst_next = dst + w_bytes;

    return rem_bytes ? ret : JSTokenizer::EOS;
}

size_t JSNormalizer::size()
{
    return sizeof(JSNormalizer) + 16834; // the default YY_BUF_SIZE
}
