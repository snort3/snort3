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

#include <FlexLexer.h>

#include "js_tokenizer.h"

using namespace snort;

int JSNormalizer::normalize(const char* srcbuf, uint16_t srclen, char* dstbuf, uint16_t dstlen,
        const char** ptr, int* bytes_copied, JSNormState& state)
{
    std::stringstream in, out;
    in.rdbuf()->pubsetbuf(const_cast<char*>(srcbuf),
        (state.norm_depth >= srclen) ? srclen : state.norm_depth);

    JSTokenizer tokenizer(in, out, dstbuf, dstlen, ptr, bytes_copied, state);
    return tokenizer.yylex();
}

