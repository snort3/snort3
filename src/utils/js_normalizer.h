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
// js_normalizer.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef JS_NORMALIZER_H
#define JS_NORMALIZER_H

#include "main/snort_types.h"

#include <FlexLexer.h>

#include "js_tokenizer.h"

namespace snort
{

class JSNormalizer
{
public:
    JSNormalizer();

    const char* get_src_next() const
    { return src_next; }

    char* get_dst_next() const // this can go beyond dst length, but no writing happens outside of dst
    { return dst_next; }

    void reset_depth()
    { rem_bytes = depth; }

    void set_depth(size_t depth);

    JSTokenizer::JSRet normalize(const char* src, size_t src_len, char* dst, size_t dst_len);

    static size_t size();

private:
    size_t depth;
    size_t rem_bytes;
    bool unlim;
    const char* src_next;
    char* dst_next;

    std::stringstream in;
    std::stringstream out;
    JSTokenizer tokenizer;
};

}

#endif //JS_NORMALIZER_H

