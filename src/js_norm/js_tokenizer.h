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

#include <array>
#include <sstream>
#include <stack>
#include <vector>

#include "log/messages.h"
#include "trace/trace_api.h"

extern THREAD_LOCAL const snort::Trace* js_trace;

// The longest pattern has 9 characters " < / s c r i p t > ",
// 8 of them can reside in 1st chunk
// Each character in the identifier forms its own group (pattern matching case),
// i.e. in the current implementation IDENTIFIER has " . " rule.
#define JSTOKENIZER_MAX_STATES 8

// To hold potentially long identifiers
#define JSTOKENIZER_BUF_MAX_SIZE 256

namespace jsn
{

enum JSProgramScopeType : unsigned int;

class JSIdentifier;
#if defined(CATCH_TEST_BUILD) || defined(BENCHMARK_TEST)
class JSTokenizerTester;
class JSTestConfig;
#endif // CATCH_TEST_BUILD || BENCHMARK_TEST

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
        ARROW_FUNCTION, // arrow function
        FUNCTION,       // function
        BLOCK,          // if, else, for, while, do, with, switch, try, catch, finally, block of code
        OBJECT,         // object definition, class definition
        SCOPE_META_TYPE_MAX
    };
    enum FuncType
    {
        NOT_FUNC = 0,
        GENERAL,
        UNESCAPE,
        CHAR_CODE
    };
    struct Scope
    {
        Scope(ScopeType t) :
            type(t), meta_type(ScopeMetaType::NOT_SET), func_call_type(FuncType::NOT_FUNC),
            ident_norm(true), block_param(false), do_loop(false), encoding(0), char_code_str(false),
            in_object(false)
        {}

        ScopeType type;
        ScopeMetaType meta_type;
        FuncType func_call_type;
        bool ident_norm;
        bool block_param;
        bool do_loop;
        uint32_t encoding;
        bool char_code_str;
        bool in_object;
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
        ALIAS_NEW,        // var a = new
        ALIAS_VALUE       // var a = eval
    };

    template <class T>
    using VStack = std::stack<T, std::vector<T>>;

public:
    enum JSRet
    {
        EOS = 0,
        SCRIPT_ENDED,
        SCRIPT_CONTINUE,
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
    explicit JSTokenizer(std::istream& in, std::ostream& out, JSIdentifier& ident_ctx,
        uint8_t max_template_nesting, uint32_t max_bracket_depth, char*& buf, size_t& buf_size,
        int cap_size = JSTOKENIZER_BUF_MAX_SIZE);
    ~JSTokenizer() override;

    JSRet process(size_t& bytes_in, bool external_script = false);

    void reset_output()
    { ignored_id_pos = -1; }

    bool is_unescape_nesting_seen() const;
    bool is_mixed_encoding_seen() const;
    bool is_opening_tag_seen() const;
    bool is_closing_tag_seen() const;
    bool is_buffer_adjusted() const;

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
    bool concatenate();
    void process_punctuator(JSToken tok = PUNCTUATOR);
    void skip_punctuator();
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
    void set_func_call_type(FuncType);
    FuncType func_call_type();
    FuncType detect_func_type();
    void check_function_nesting(FuncType);
    void check_mixed_encoding(uint32_t);
    void set_block_param(bool);
    bool block_param();
    void set_do_loop(bool);
    bool do_loop();

    void set_encoding(uint32_t f)
    { scope_cur().encoding |= f; }

    uint32_t encoding()
    { return scope_cur().encoding; }

    void set_char_code_str(bool f)
    { scope_cur().char_code_str = f; }

    bool char_code_str()
    { return scope_cur().char_code_str; }

    void set_in_object(bool f)
    { scope_cur().in_object = f; }

    bool in_object()
    { return scope_cur().in_object; }

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

    //rule handlers
    JSRet html_closing_script_tag();
    JSRet literal_dq_string_start();
    JSRet literal_sq_string_start();
    JSRet literal_template_start();
    JSRet literal_regex_start();
    JSRet literal_regex_end();
    JSRet literal_regex_g_open();
    JSRet literal_regex_g_close();
    void div_assignment_operator();
    JSRet open_brace();
    JSRet close_brace();
    JSRet open_parenthesis();
    JSRet close_parenthesis();
    JSRet open_bracket();
    JSRet close_bracket();
    JSRet punctuator_prefix();
    void dot_accessor();
    JSRet punctuator_arrow();
    JSRet punctuator_semicolon();
    void punctuator_colon();
    void operator_comparison();
    void operator_complex_assignment();
    void operator_logical();
    void operator_shift();
    void punctuator_comma();
    JSRet use_strict_directive();
    JSRet use_strict_directive_sc();
    JSRet keyword_var_decl();
    JSRet keyword_function();
    JSRet keyword_catch();
    JSRet keyword_while();
    JSRet keyword_B();
    JSRet keyword_new();
    JSRet keyword_BA();
    JSRet keyword_finally();
    JSRet keyword_do();
    JSRet keyword_class();
    JSRet keyword_other();
    void operator_assignment();
    JSRet operator_prefix();
    JSRet operator_incr_decr();
    JSRet general_operator();
    JSRet general_literal();
    JSRet general_identifier();
    void general_unicode();
    void escaped_unicode_latin_1();
    void escaped_unicode_utf_8();
    void escaped_code_point();
    void escaped_url_sequence_latin_1();
    void lit_int_code_point(int base);
    void char_code_no_match();
    void explicit_otag();
    void ctag_in_regex();

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
    bool unescape_nest_seen = false;
    bool mixed_encoding_seen = false;
    bool opening_tag_seen = false;
    bool closing_tag_seen = false;

    uint8_t max_template_nesting;
    VStack<uint16_t> brace_depth;
    JSToken token = UNDEFINED;
    ASIGroup previous_group = ASI_OTHER;
    JSIdentifier& ident_ctx;
    size_t bytes_read;
    size_t tmp_bytes_read;
    uint32_t tokens_read;
    uint32_t tmp_tokens_read;
    bool ext_script;
    VStack<char> regex_stack;

    struct
    {
        JSToken token = UNDEFINED;          // the token before
        int orig_len = 0;                   // current token original length
        int norm_len = 0;                   // normalized length of previous tokens
        int sc = 0;                         // current Starting Condition (0 means NOT_SET)
        int correction = 0;                 // correction length
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
    bool adjusted_data = false;              // flag for resetting the continuation in case of adjusting js_data
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

    std::streampos ignored_id_pos;
    struct FunctionIdentifier
    {
        bool operator< (const FunctionIdentifier& other) const
        { return identifier.size() < other.identifier.size(); }

        std::string identifier;
        FuncType type;
    };

    const std::array<FunctionIdentifier, 5> function_identifiers
    {{
        {"unescape",             FuncType::UNESCAPE },
        {"decodeURI",            FuncType::UNESCAPE },
        {"decodeURIComponent",   FuncType::UNESCAPE },
        {"String.fromCharCode",  FuncType::CHAR_CODE},
        {"String.fromCodePoint", FuncType::CHAR_CODE}
    }};

    const uint32_t max_bracket_depth;
    std::stack<Scope> scope_stack;

#if defined(CATCH_TEST_BUILD) || defined(BENCHMARK_TEST)
    friend JSTokenizerTester;
    friend JSTestConfig;
#endif // CATCH_TEST_BUILD || BENCHMARK_TEST
};

}

#endif // JS_TOKENIZER_H
