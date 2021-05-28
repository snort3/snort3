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
// js_tokenizer.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef JS_TOKENIZER_H
#define JS_TOKENIZER_H

#include <sstream>

#include "log/messages.h"

class JSTokenizer : public yyFlexLexer
{
private:
    enum JSToken
    {
        UNDEFINED = 0,
        IDENTIFIER,
        KEYWORD,
        PUNCTUATOR,
        OPERATOR,
        LITERAL,
        DIRECTIVE
    };

public:
    enum JSRet
    {
        EOS = 0,
        SCRIPT_ENDED,
        SCRIPT_CONTINUE,
        OPENING_TAG,
        CLOSING_TAG,
        BAD_TOKEN
    };

    JSTokenizer(std::istream& in, std::ostream& out);
    ~JSTokenizer() override;

    // returns JSRet
    int yylex() override;

protected:
    [[noreturn]] void LexerError(const char* msg) override
    { snort::FatalError("%s", msg); }

private:
    void switch_to_initial();
    void switch_to_temporal(const std::string& data);
    JSRet eval_eof();
    JSRet do_spacing(JSToken cur_token);
    JSRet do_operator_spacing(JSToken cur_token);
    bool unescape(const char* lexeme);

private:
    void* cur_buffer;
    void* tmp_buffer = nullptr;
    std::stringstream tmp;

    JSToken token = UNDEFINED;
};

#endif // JS_TOKENIZER_H

