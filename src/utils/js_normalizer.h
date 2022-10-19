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
// js_normalizer.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef JS_NORMALIZER_H
#define JS_NORMALIZER_H

#include "main/snort_types.h"

#include <FlexLexer.h>

#include "js_tokenizer.h"
#include "streambuf.h"

namespace snort
{

class JSNormalizer
{
public:
    JSNormalizer(JSIdentifierCtxBase& js_ident_ctx, size_t depth,
        uint8_t max_template_nesting, uint32_t max_bracket_depth,
        int tmp_cap_size = JSTOKENIZER_BUF_MAX_SIZE);
    ~JSNormalizer();

    JSTokenizer::JSRet normalize(const char* src, size_t src_len,
        bool external_script = false);

    const char* get_src_next() const
    { return src_next; }

    void reset_depth()
    { rem_bytes = depth; }

    const char* take_script()
    { tokenizer.reset_output(); return out_buf.take_data(); }

    const char* get_script() const
    { return out_buf.data(); }

    size_t script_size()
    { return out.tellp(); }

    static size_t size()
    { return sizeof(JSNormalizer) + 16834; /* YY_BUF_SIZE */ }

    bool is_unescape_nesting_seen() const
    { return tokenizer.is_unescape_nesting_seen(); }

    bool is_mixed_encoding_seen() const
    { return tokenizer.is_mixed_encoding_seen(); }

    bool is_opening_tag_seen() const
    { return tokenizer.is_opening_tag_seen(); }

    bool is_closing_tag_seen() const
    { return tokenizer.is_closing_tag_seen(); }

    bool is_buffer_adjusted() const
    { return tokenizer.is_buffer_adjusted(); }

#if defined(CATCH_TEST_BUILD) || defined(BENCHMARK_TEST)
    const char* get_tmp_buf() const
    { return tmp_buf; }
    size_t get_tmp_buf_size() const
    { return tmp_buf_size; }
    const JSTokenizer& get_tokenizer() const
    { return tokenizer; }
#endif // CATCH_TEST_BUILD || BENCHMARK_TEST

#ifdef BENCHMARK_TEST
    void rewind_output()
    { out_buf.pubseekoff(0, std::ios_base::beg, std::ios_base::out); }
#endif

private:
    size_t depth;
    size_t rem_bytes;
    bool unlim;
    const char* src_next;

    char* tmp_buf;
    size_t tmp_buf_size;

    istreambuf_glue in_buf;
    ostreambuf_infl out_buf;
    std::istream in;
    std::ostream out;
    JSTokenizer tokenizer;
};

}

#endif //JS_NORMALIZER_H
