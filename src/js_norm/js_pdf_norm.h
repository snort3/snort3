//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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
// js_pdf_norm.h author Cisco

#ifndef JS_PDF_NORM_H
#define JS_PDF_NORM_H

#include <FlexLexer.h>
#include <cstring>

#include "js_norm/js_norm.h"
#include "js_norm/pdf_tokenizer.h"
#include "utils/streambuf.h"

namespace snort
{

class SO_PUBLIC PDFJSNorm : public JSNorm
{
public:
    static bool is_pdf(const void* data, size_t len)
    {
        constexpr char magic[] = "%PDF-1.";
        constexpr int magic_len = sizeof(magic) - 1;
        return magic_len < len and !strncmp((const char*)data, magic, magic_len);
    }

    PDFJSNorm(JSNormConfig* cfg) :
        JSNorm(cfg), pdf_in(&buf_pdf_in), pdf_out(&buf_pdf_out), extractor(pdf_in, pdf_out)
    { }

protected:
    bool pre_proc() override;
    bool post_proc(int) override;

private:
    snort::istreambuf_glue buf_pdf_in;
    snort::ostreambuf_infl buf_pdf_out;
    std::istream pdf_in;
    std::ostream pdf_out;
    jsn::PDFTokenizer extractor;
};

}

#endif
