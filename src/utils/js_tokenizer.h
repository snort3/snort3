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
#include <stack>
#include <vector>

#include "log/messages.h"
#include "main/snort_debug.h"
#include "service_inspectors/http_inspect/http_enum.h"

extern THREAD_LOCAL const snort::Trace* http_trace;

// The longest pattern has 9 characters " < / s c r i p t > ",
// 8 of them can reside in 1st chunk
// Each character in the identifier forms its own group (pattern matching case),
// i.e. in the current implementation IDENTIFIER has " . " rule.
#define JSTOKENIZER_MAX_STATES 8

// To hold potentially long identifiers
#define JSTOKENIZER_BUF_MAX_SIZE 256

class JSIdentifierCtxBase;

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
        BAD_TOKEN,
        IDENTIFIER_OVERFLOW,
        TEMPLATE_NESTING_OVERFLOW,
        MAX
    };

    JSTokenizer(std::istream& in, std::ostream& out, JSIdentifierCtxBase& ident_ctx,
        uint8_t max_template_nesting, char*& buf, size_t& buf_size,
        int cap_size = JSTOKENIZER_BUF_MAX_SIZE);
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
    JSRet do_identifier_substitution(const char* lexeme);
    bool unescape(const char* lexeme);
    void process_punctuator();
    void process_closing_bracket();
    JSRet process_subst_open();

    void states_push();
    void states_apply();
    void states_correct(int);

    void* cur_buffer;
    void* tmp_buffer = nullptr;
    std::stringstream tmp;
    uint8_t max_template_nesting;
    std::stack<uint16_t, std::vector<uint16_t>> bracket_depth;
    JSToken token = UNDEFINED;
    JSIdentifierCtxBase& ident_ctx;

    struct
    {
        JSToken token = UNDEFINED;          // the token before
        int length = 0;                     // current token length
        int sc = 0;                         // current Starting Condition
    } states[JSTOKENIZER_MAX_STATES];
    int sp = 0;                             // points to the top of states

    char*& tmp_buf;
    size_t& tmp_buf_size;
    const int tmp_cap_size;
};

#endif // JS_TOKENIZER_H

