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

class gluebuf : public std::stringbuf
{
public:
    gluebuf() :
        std::stringbuf(), once(true),
        src1(nullptr), len1(0), src2(nullptr), len2(0)
    { }

    std::streambuf* str(char* buf1, std::streamsize buf1_len,
        char* buf2, std::streamsize buf2_len)
    {
        once = !(buf1 && buf1_len);

        if (once)
        {
            std::stringbuf::str(std::string(buf2, buf2_len));
            current_src_len = buf2_len;
        }
        else
        {
            std::stringbuf::str(std::string(buf1, buf1_len));
            current_src_len = buf1_len;
        }
        src1 = buf1;
        len1 = buf1_len;
        src2 = buf2;
        len2 = buf2_len;
        return this;
    }

    bool glued() const
    {
        return once;
    }

protected:
    virtual std::streampos seekoff(std::streamoff off,
        std::ios_base::seekdir way, std::ios_base::openmode which) override
    {
        if (way != std::ios_base::end)
            return std::stringbuf::seekoff(off, way, which);

        if (current_src_len + off < 0 and once)
        {
            debug_logf(6, http_trace, TRACE_JS_PROC, nullptr,
                "seek offset %ld, %p:%zu => %p:%zu\n",
                off, src2, len2, src1, len1);

            off += current_src_len;
            once = false;
            std::stringbuf::str(std::string(src1, len1));
            current_src_len = len1;
        }

        return std::stringbuf::seekoff(off, way, which);
    }

    virtual int underflow() override
    {
        if (once)
        {
            debug_log(6, http_trace, TRACE_JS_PROC, nullptr,
                "underflow, no buffer to switch to\n");
            return EOF;
        }

        debug_logf(6, http_trace, TRACE_JS_PROC, nullptr,
            "underflow, %p:%zu => %p:%zu\n",
            src1, len1, src2, len2);

        once = true;
        std::stringbuf::str(std::string(src2, len2));
        current_src_len = len2;
        return sgetc();
    }

private:
    bool once;
    std::streamsize current_src_len;
    char* src1;
    std::streamsize len1;
    char* src2;
    std::streamsize len2;
};

class JSNormalizer
{
public:
    JSNormalizer(JSIdentifierCtxBase& js_ident_ctx, size_t depth,
        uint8_t max_template_nesting, int tmp_cap_size = JSTOKENIZER_BUF_MAX_SIZE);
    ~JSNormalizer();

    const char* get_src_next() const
    { return src_next; }

    char* get_dst_next() const // this can go beyond dst length, but no writing happens outside of dst
    { return dst_next; }

    void reset_depth()
    { rem_bytes = depth; }

    JSTokenizer::JSRet normalize(const char* src, size_t src_len, char* dst, size_t dst_len);

    static size_t size();

private:
    size_t depth;
    size_t rem_bytes;
    bool unlim;
    const char* src_next;
    char* dst_next;

    char* tmp_buf;
    size_t tmp_buf_size;

    gluebuf in_buf;
    std::stringbuf out_buf;
    std::istream in;
    std::ostream out;
    JSTokenizer tokenizer;
};

}

#endif //JS_NORMALIZER_H
