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

enum JSProgramScopeType : unsigned int;

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
        DIRECTIVE,
        DOT,
        COLON,
        CLOSING_BRACKET,
        KEYWORD_VAR_DECL,             // var, let, const
        KEYWORD_FUNCTION,
        KEYWORD_BLOCK,                // for all block-definition keywords e.g. if, else, for, etc.
        KEYWORD_CLASS,
        OPERATOR_ASSIGNMENT,
        OPERATOR_COMPLEX_ASSIGNMENT,
        OPERATOR_COMPARISON,
        OPERATOR_LOGICAL,
        OPERATOR_SHIFT
    };

    enum ScopeType
    {
        GLOBAL = 0,  // not in the brackets (the initial one)
        BRACES,      // {}
        PARENTHESES, // ()
        BRACKETS     // []
    };
    enum ScopeMetaType
    {
        NOT_SET = 0,
        FUNCTION,   // function, arrow function
        BLOCK,      // if, else, for, while, do, with, switch, try, catch, finally, block of code
        OBJECT,     // object definition, class definition
        SCOPE_META_TYPE_MAX
    };
    struct Scope
    {
        Scope(ScopeType t) :
            type(t), meta_type(ScopeMetaType::NOT_SET), ident_norm(true), func_call(false),
            block_param(false), do_loop(false)
        {}

        ScopeType type;
        ScopeMetaType meta_type;
        bool ident_norm;
        bool func_call;
        bool block_param;
        bool do_loop;
    };

    enum ASIGroup
    {
        ASI_OTHER = 0,
        ASI_GROUP_1,    // {
        ASI_GROUP_2,    // }
        ASI_GROUP_3,    // [ (
        ASI_GROUP_4,    // ]
        ASI_GROUP_5,    // )
        ASI_GROUP_6,    // + -
        ASI_GROUP_7,    // this true false null identifier literal
                        //IDENTIFIER + LITERAL + KEYWORD_LITERAL
        ASI_GROUP_8,    // ++ --
        ASI_GROUP_9,    // continue break return debugger // same as KEYWORD_BA
        ASI_GROUP_10,   // var function new delete void typeof if do while for with
                        // switch throw try ~ +
        ASI_GROUP_MAX
    };

    enum AliasState
    {
        ALIAS_NONE = 0,
        ALIAS_DEFINITION, // var a
        ALIAS_PREFIX,     // var a +%possible PDU split%
                          // to handle ambiguity between a++, a+=, and a + b
        ALIAS_EQUALS,     // var a =
        ALIAS_VALUE       // var a = eval
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
        BRACKET_NESTING_OVERFLOW,
        SCOPE_NESTING_OVERFLOW,
        WRONG_CLOSING_SYMBOL,
        ENDED_IN_INNER_SCOPE,
        MAX
    };

    JSTokenizer() = delete;
    explicit JSTokenizer(std::istream& in, std::ostream& out, JSIdentifierCtxBase& ident_ctx,
        uint8_t max_template_nesting, uint32_t max_bracket_depth, char*& buf, size_t& buf_size,
        int cap_size = JSTOKENIZER_BUF_MAX_SIZE);
    ~JSTokenizer() override;

    JSRet process(size_t& bytes_in);

protected:
    [[noreturn]] void LexerError(const char* msg) override
    { snort::FatalError("%s", msg); }

private:
    int yylex() override;

    void switch_to_initial();
    void switch_to_temporal(const std::string& data);
    JSRet eval_eof();
    JSRet do_spacing(JSToken cur_token);
    JSRet do_operator_spacing();
    JSRet do_semicolon_insertion(ASIGroup current);
    JSRet do_identifier_substitution(const char* lexeme, bool id_part);
    JSRet push_identifier(const char* ident);
    bool unescape(const char* lexeme);
    void process_punctuator(JSToken tok = PUNCTUATOR);
    void process_closing_brace();
    JSRet process_subst_open();

    bool states_process();
    void states_correct(int);
    void states_reset();
    void states_over();
    void states_adjust();

    // scope stack servicing
    JSRet scope_push(ScopeType);
    JSRet scope_pop(ScopeType);
    Scope& scope_cur();

    // program scope stack servicing
    JSRet p_scope_push(ScopeMetaType);
    JSRet p_scope_pop(ScopeMetaType);

    // interactions with the current scope
    bool global_scope();
    void set_meta_type(ScopeMetaType);
    ScopeMetaType meta_type();
    void set_ident_norm(bool);
    bool ident_norm();
    void set_func_call(bool);
    bool func_call();
    void set_block_param(bool);
    bool block_param();
    void set_do_loop(bool);
    bool do_loop();

    static JSProgramScopeType m2p(ScopeMetaType);
    static const char* m2str(ScopeMetaType);
    static bool is_operator(JSToken);

    void dealias_clear_mutated(bool id_part);
    void dealias_increment();
    void dealias_identifier(bool id_part, bool assignment_start);
    void dealias_reset();
    void dealias_prefix_reset();
    void dealias_equals(bool complex);
    void dealias_append();
    void dealias_finalize();

    static const char* p_scope_codes[];

    void* cur_buffer;
    void* tmp_buffer = nullptr;
    std::stringstream tmp;

    std::stringstream aliased;
    std::string alias;
    std::string last_dealiased;
    AliasState alias_state = ALIAS_NONE;
    bool prefix_increment = false;
    bool dealias_stored = false;

    uint8_t max_template_nesting;
    std::stack<uint16_t, std::vector<uint16_t>> brace_depth;
    JSToken token = UNDEFINED;
    ASIGroup previous_group = ASI_OTHER;
    JSIdentifierCtxBase& ident_ctx;
    size_t bytes_read;
    size_t tmp_bytes_read;

    struct
    {
        JSToken token = UNDEFINED;          // the token before
        int orig_len = 0;                   // current token original length
        int norm_len = 0;                   // normalized length of previous tokens
        int sc = 0;                        // current Starting Condition (0 means NOT_SET)
    } states[JSTOKENIZER_MAX_STATES];
    int sp = 0;                             // points to the top of states
    int eof_sp = 0;                         // points to the last state before the EOF
    JSToken eof_token = UNDEFINED;          // the last token before the EOF
    int eof_sc = 0;                         // the last Starting Condition before the EOF
    int bytes_skip = 0;                     // num of bytes to skip of processing in the next chunk

    char*& tmp_buf;
    size_t& tmp_buf_size;
    const int tmp_cap_size;

    bool newline_found = false;
    constexpr static bool insert_semicolon[ASI_GROUP_MAX][ASI_GROUP_MAX]
    {
        {false, false, false, false, false, false, false, false, false, false, false,},
        {false, false, false, false, false, false, false, false, false, false, false,},
        {false, false, false, false, false, false, false, false, false, false, false,},
        {false, false, false, false, false, false, false, false, false, false, false,},
        {false, true,  false, false, false, false, false, true,  true,  true,  true, },
        {false, false, false, false, false, false, false, true,  true,  true,  true, },
        {false, false, false, false, false, false, false, false, false, false, false,},
        {false, true,  false, false, false, false, false, true,  true,  true,  true, },
        {false, true,  false, true,  false, false, false, true,  true,  true,  true, },
        {false, true,  false, true,  false, false, true,  true,  true,  true,  true, },
        {false, false, false, false, false, false, false, false, false, false, false,}
    };

    const uint32_t max_bracket_depth;
    std::stack<Scope> scope_stack;
};

#endif // JS_TOKENIZER_H
