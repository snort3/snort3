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

#include "js_norm_state.h"

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
    // we need an out stream because yyFlexLexer API strongly requires that
    JSTokenizer(std::stringstream& in, std::stringstream& out, char* dstbuf,
        const uint16_t dstlen, const char** ptr, int* bytes_copied, snort::JSNormState& state);
    ~JSTokenizer() override;

    // so, Flex will treat this class as yyclass
    // must come with yyclass Flex option
    // don't need to define this method, it'll be substituted by Flex
    // returns 0 if OK, 1 otherwise
    int yylex() override;

protected:
    [[noreturn]] void LexerError(const char* msg) override
    { snort::FatalError("%s", msg); }

private:
    void init();

    // scan buffers control
    void switch_to_temporal(const std::string& data);
    void switch_to_initial();

    bool eval_identifier(const char* lexeme);
    bool eval_string_literal(const char* match_prefix, const char quotes);
    bool eval_regex_literal(const char* match_prefix);
    bool eval_eof();
    bool eval_single_line_comment();
    bool eval_multi_line_comment();

    bool parse_literal(const std::string& match_prefix, const char sentinel_ch,
        std::string& result, bool& is_alert, bool is_regex = false);

    // main lexeme handler
    // all scanned tokens must pass here
    bool eval(const JSToken tok, const char* lexeme);

    bool normalize_identifier(const JSToken prev_tok, const char* lexeme);
    bool normalize_punctuator(const JSToken prev_tok, const char* lexeme);
    bool normalize_operator(const JSToken prev_tok, const char* lexeme);
    bool normalize_directive(const JSToken prev_tok, const char* lexeme);
    bool normalize_undefined(const JSToken prev_tok, const char* lexeme);
    bool normalize_lexeme(const JSToken prev_tok, const char* lexeme);

    bool write_output(const std::string& str);

    void update_ptr();

private:
    char* dstbuf;
    const uint16_t dstlen;
    const char** ptr;
    int* bytes_copied;

    struct ScanBuffers;
    ScanBuffers* buffers = nullptr;
    std::stringstream temporal;

    JSToken prev_tok = UNDEFINED;

    snort::JSNormState& state;

};

#endif // JS_TOKENIZER_H

