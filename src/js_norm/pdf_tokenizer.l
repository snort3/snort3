/*--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// pdf_tokenizer.l author Cisco
*/

%option c++
%option yyclass="PDFTokenizer"
%option prefix="pdf"
%option align full 8bit batch never-interactive stack
%option noinput nounput noyywrap noyy_top_state

%{

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <cassert>

#include "js_norm/js_enum.h"
#include "js_norm/pdf_tokenizer.h"
#include "log/messages.h"
#include "trace/trace_api.h"

extern THREAD_LOCAL const snort::Trace* js_trace;

using namespace jsn;

#define YY_NO_UNPUT

#define YY_FATAL_ERROR(msg) { snort::FatalError("%s", msg); }

#define PUSH(x) yy_push_state(x)
#define POP() yy_pop_state()

#define YY_USER_ACTION                                                         \
    {                                                                          \
        debug_logf(5, js_trace, TRACE_PDF_PROC, nullptr,                       \
            "PDF pattern #%d, sc %d\n", yy_act, YY_START);                     \
        debug_logf(5, js_trace, TRACE_PDF_DUMP, nullptr,                       \
            "PDF text '%s'\n", YYText());                                      \
    }

#define EXEC(f)                                                                \
    {                                                                          \
        auto r = (f);                                                          \
        if (r)                                                                 \
            return r;                                                          \
    }

%}

/* PDF 32000-1:2008 definitions follow */

/* 7.2.2 Character Set */
CHARS_WHITESPACE   \x00\x09\x0a\x0c\x0d\x20
CHARS_DELIMITER    \(\)\<\>\[\]\{\}\/\%
GRP_WHITESPACE     [\x00\x09\x0a\x0c\x0d\x20]
EOL_MARKER         \r|\n|\r\n
GRP_NEWLINE        [\x0d\x0a]
GRP_NOT_NEWLINE    [^\x0d\x0a]
GRP_DELIMITER      [\(\)\<\>\[\]\{\}\/\%]
GRP_REGULAR        [^\x00\x09\x0a\x0c\x0d\x20\(\)\<\>\[\]\{\}\/\%]

/* 7.2.3 Comments */
COMMENT_START      %
COMMENT_CONTENT    {GRP_NOT_NEWLINE}{1,16}
COMMENT_END        {EOL_MARKER}

/* 7.3.2 Boolean Objects */
OBJ_BOOLEAN        true|false

/* 7.3.3 Numeric Objects */
OBJ_INT_NUM        [+-]?[0-9]{1,16}
OBJ_REL_NUM        [+-]?("."?[0-9]{1,16}|[0-9]{1,16}"."?|[0-9]{1,16}"."?[0-9]{1,16})

/* 7.3.4 String Objects */
OBJ_LIT_STR_OPEN   "("
OBJ_LIT_STR_CLOSE  ")"
OBJ_HEX_STR_OPEN   "<"
OBJ_HEX_STR_CLOSE  ">"

/* 7.3.4.2 Literal Strings */
LIT_STR_ESC        \\[^0-7]
LIT_STR_ESC_OCT    \\[0-7]{1}|\\[0-7]{2}|\\[0-7]{3}
LIT_STR_ESC_EOL    \\[\x0d\x0a]|\\\x0d\x0a
LIT_STR_EOL        [\x0d\x0a]|\x0d\x0a
LIT_STR_BODY       [^\\\(\)]{1,16}

/* 7.9.2.2 Text String Type, UTF-16BE */
/* RFC 2781: 4.3 Interpreting text labelled as UTF-16 */
U16_BOM            \xfe\xff
U16_BOM_HEX        FE{HEX_STR_SKIP}*FF
LIT_STR_U16_UNESC  \\[(\)\\nrtbf]
LIT_STR_U16_BODY   [^\\\(\)]{1,16}

/* 7.3.4.3 Hexadecimal Strings */
HEX_STR_BODY       [0-9A-Fa-f]{1,16}
HEX_STR_SKIP       [^0-9A-Fa-f>]{1,16}

/* 7.3.5 Name Objects */
OBJ_NAME           \/{GRP_REGULAR}{1,256}

/* 7.3.6 Array Objects */
OBJ_ARRAY_OPEN     "["
OBJ_ARRAY_CLOSE    "]"

/* 7.3.7 Dictionary Objects */
OBJ_DICT_OPEN      "<<"
OBJ_DICT_CLOSE     ">>"

OBJ_DICT_SKIP      .|{GRP_NEWLINE}

/* 7.3.8 Stream Objects */
OBJ_STREAM_OPEN    stream\r?\n
OBJ_STREAM_CLOSE   {EOL_MARKER}endstream
OBJ_STREAM_SKIP    {GRP_NOT_NEWLINE}{1,16}|{GRP_NEWLINE}

/* 7.3.9 Null Object */
OBJ_NULL           null

/* 7.3.10 Indirect Objects */
INDIRECT_OBJ_OPEN  {OBJ_INT_NUM}{GRP_WHITESPACE}+{OBJ_INT_NUM}{GRP_WHITESPACE}+obj

INDIRECT_OBJ_CLOSE endobj

OBJ_REFERENCE        {OBJ_INT_NUM}{GRP_WHITESPACE}+{OBJ_INT_NUM}{GRP_WHITESPACE}+R


/* Not object start, not comments */
SKIP              [^[:digit:]%]{1,16}|.
WHITESPACE        {GRP_WHITESPACE}{1,16}

/* Start conditions: structures: comment, indirect object, dictionary or array */
%x comment
%x indobj
%x dictnr

/* Start conditions: literals: regular, hexadecimal, stream */
%x litstr
%x hexstr
%x stream
%x jslstr
%x jshstr
%x jsstream

/* Start conditions: UTF-16BE: BOM, hex BOM, regular, hexadecimal, stream */
%x u16
%x u16hex
%x jsstru16
%x jshstru16
%x jsstreamu16

%%


<INITIAL,indobj,dictnr>{COMMENT_START}            { PUSH(comment); }
<comment>{COMMENT_CONTENT}                        { }
<comment>{COMMENT_END}                            { POP(); }

<INITIAL>{INDIRECT_OBJ_OPEN}                      { PUSH(indobj); h_ind_obj_open(); }
<indobj>{WHITESPACE}                              { }
<indobj>{INDIRECT_OBJ_CLOSE}                      { POP(); h_ind_obj_close(); }

<indobj>{OBJ_STREAM_OPEN}                         { EXEC(h_stream_open()) PUSH(obj_stream.is_js ? u16 : stream); }
<stream>{OBJ_STREAM_SKIP}                         { EXEC(h_stream()) }
<jsstream>{OBJ_STREAM_SKIP}                       { EXEC(h_stream()) ECHO; }
<jsstreamu16>{OBJ_STREAM_SKIP}                    { EXEC(h_stream()) EXEC(h_lit_u16()) }
<stream>{OBJ_STREAM_CLOSE}                        { if (h_stream_close()) POP(); }
<jsstream>{OBJ_STREAM_CLOSE}                      { if (h_stream_close()) POP(); }
<jsstreamu16>{OBJ_STREAM_CLOSE}                   { if (h_stream_close()) POP(); }

<dictnr>{OBJ_DICT_OPEN}                           { PUSH(dictnr); EXEC(h_dict_open()) }
<indobj>{OBJ_DICT_OPEN}                           { PUSH(dictnr); EXEC(h_dict_open()) }
<dictnr>{OBJ_DICT_CLOSE}                          { POP(); EXEC(h_dict_close()) }
<dictnr>{WHITESPACE}                              { }
<dictnr>{OBJ_REFERENCE}                           { EXEC(h_dict_other()) h_ref(); }
<dictnr>{OBJ_BOOLEAN}                             { EXEC(h_dict_other()) }
<dictnr>{OBJ_INT_NUM}                             { EXEC(h_dict_other()) h_stream_length(); }
<dictnr>{OBJ_REL_NUM}                             { EXEC(h_dict_other()) }
<dictnr>{OBJ_NULL}                                { EXEC(h_dict_other()) }
<dictnr>{OBJ_NAME}                                { EXEC(h_dict_name()) }
<dictnr>{OBJ_ARRAY_OPEN}                          { ++obj_array.nesting_level; EXEC(h_dict_other()) }
<dictnr>{OBJ_ARRAY_CLOSE}                         { --obj_array.nesting_level; EXEC(h_dict_other()) }
<dictnr>{OBJ_LIT_STR_OPEN}                        { EXEC(h_dict_other()) if (h_lit_str()) PUSH(jslstr); else PUSH(litstr); yyless(0); }
<dictnr>{OBJ_HEX_STR_OPEN}                        { EXEC(h_dict_other()) if (h_hex_str()) PUSH(jshstr); else PUSH(hexstr); yyless(0); }
<dictnr>{OBJ_DICT_SKIP}                           { }

<indobj>{OBJ_LIT_STR_OPEN}                        { if (h_lit_open()) PUSH(litstr); }
<litstr>{OBJ_LIT_STR_OPEN}                        { h_lit_open(); }
<litstr>{OBJ_LIT_STR_CLOSE}                       { if (h_lit_close()) POP(); }
<litstr>{LIT_STR_ESC}                             { }
<litstr>{LIT_STR_ESC_OCT}                         { }
<litstr>{LIT_STR_ESC_EOL}                         { }
<litstr>{LIT_STR_EOL}                             { }
<litstr>{LIT_STR_BODY}                            { }

<indobj>{OBJ_HEX_STR_OPEN}                        { PUSH(hexstr); }
<hexstr>{OBJ_HEX_STR_CLOSE}                       { POP(); }
<hexstr>{HEX_STR_BODY}                            { }
<hexstr>{HEX_STR_SKIP}                            { }

<jslstr>{OBJ_LIT_STR_OPEN}                        { if (!h_lit_open()) ECHO; else PUSH(u16); }
<jslstr>{OBJ_LIT_STR_CLOSE}                       { if (h_lit_close()) POP(); else ECHO; }
<jslstr>{LIT_STR_ESC}                             { EXEC(h_lit_unescape()) }
<jslstr>{LIT_STR_ESC_OCT}                         { EXEC(h_lit_oct2chr()) }
<jslstr>{LIT_STR_ESC_EOL}{WHITESPACE}             { }
<jslstr>{LIT_STR_EOL}                             { ECHO; }
<jslstr>{LIT_STR_BODY}                            { ECHO; }

<u16>{U16_BOM}                                    { h_u16_start(); }
<u16>.|\n                                         { h_u16_break(); }

<jsstru16>{OBJ_LIT_STR_CLOSE}                     { if (h_lit_close()) POP(); }
<jsstru16>{LIT_STR_ESC_EOL}                       { }
<jsstru16>{LIT_STR_U16_UNESC}                     { EXEC(h_lit_u16_unescape()) }
<jsstru16>{LIT_STR_U16_BODY}                      { EXEC(h_lit_u16()) }

<u16hex>{U16_BOM_HEX}                             { h_u16_hex_start(); }
<u16hex>.|\n                                      { h_u16_hex_break(); }

<jshstr>{OBJ_HEX_STR_OPEN}                        { PUSH(u16hex); }
<jshstr,jshstru16>{OBJ_HEX_STR_CLOSE}             { POP(); }
<jshstr>{HEX_STR_BODY}                            { EXEC(h_hex_hex2chr()) }
<jshstru16>{HEX_STR_BODY}                         { EXEC(h_hex_hex2chr_u16()) }
<jshstr,jshstru16>{HEX_STR_SKIP}                  { }

<*><<EOF>>                                        { return PDFRet::EOS; }

{SKIP}                                            { }
<*>.|\n                                           { return PDFRet::UNEXPECTED_SYMBOL; }

%%

PDFTokenizer::PDFRet PDFTokenizer::h_dict_open()
{
    obj_dictionary.clear();
    obj_dictionary.array_level = obj_array.nesting_level;

    debug_logf(6, js_trace, TRACE_PDF_PROC, nullptr,
        "dictionary open, at array level %d\n", obj_array.nesting_level);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_dict_close()
{
    obj_dictionary.clear();

    debug_logf(6, js_trace, TRACE_PDF_PROC, nullptr,
        "dictionary close, at array level %d\n", obj_array.nesting_level);

    if (obj_dictionary.array_level != obj_array.nesting_level)
        return PDFRet::INCOMPLETE_ARRAY_IN_DICTIONARY;

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_dict_other()
{
    if (obj_dictionary.array_level != obj_array.nesting_level)
        return PDFRet::EOS;

    if (obj_dictionary.key_value)
        return PDFRet::NOT_NAME_IN_DICTIONARY_KEY;

    debug_logf(6, js_trace, TRACE_PDF_PROC, nullptr,
        "dictionary token: other\n");

    debug_logf(6, js_trace, TRACE_PDF_DUMP, nullptr,
        "dictionary entry: %s, %s\n", obj_entry.key, yytext);

    obj_dictionary.key_value = !obj_dictionary.key_value;

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_dict_name()
{
    if (obj_dictionary.array_level != obj_array.nesting_level)
        return PDFRet::EOS;

    if (obj_dictionary.key_value)
        strncpy(obj_entry.key, yytext, sizeof(obj_entry.key) - 1);

    obj_dictionary.key_value = !obj_dictionary.key_value;

    debug_logf(6, js_trace, TRACE_PDF_PROC, nullptr,
        "dictionary token: name as %s\n", obj_dictionary.key_value ? "value" : "key");

    debug_logf(6, js_trace, TRACE_PDF_DUMP, nullptr,
        "dictionary entry: %s, %s\n", obj_entry.key, obj_dictionary.key_value ? yytext : "...");

    return PDFRet::EOS;
}

constexpr char literal_unescape(const char& input)
{
    // 7.3.4.2 Literal Strings, Table 3 Escape sequences in literal strings
    switch (input)
    {
    case 'n': return '\n';
    case 'r': return '\r';
    case 't': return '\t';
    case 'b': return '\b';
    case 'f': return '\f';
    default: return input;
    }
}

PDFTokenizer::PDFRet PDFTokenizer::h_lit_unescape()
{
    assert(yyleng == 2);
    assert(yytext[0] == '\\');

    yyout << literal_unescape(yytext[1]);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_lit_oct2chr()
{
    assert(0 < yyleng and yyleng < 5);
    assert(yytext[0] == '\\');

    unsigned v;
    sscanf(yytext + 1, "%o", &v);
    yyout << (char)v;

    debug_logf(6, js_trace, TRACE_PDF_DUMP, nullptr,
        "literal string, %s to %c \n", yytext, v);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_hex_hex2chr()
{
    int len = yyleng & ~1;
    const char* ptr = yytext;
    const char* end = yytext + len;

    while (ptr < end)
    {
        unsigned v;
        sscanf(ptr, "%02x", &v);
        yyout << (char)v;
        ptr += 2;
    }

    if (len != yyleng)
    {
        unsigned v;
        sscanf(ptr, "%01x", &v);
        yyout << (char)(v << 4);
    }

    debug_logf(6, js_trace, TRACE_PDF_DUMP, nullptr,
        "literal string, in hex: %s\n", yytext);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_hex_hex2chr_u16()
{
    int len = yyleng & ~1;
    const char* ptr = yytext;
    const char* end = yytext + len;

    while (ptr < end)
    {
        unsigned v;
        sscanf(ptr, "%02x", &v);
        EXEC(u16_eval((uint8_t)v))
        ptr += 2;
    }

    if (len != yyleng)
    {
        unsigned v;
        sscanf(ptr, "%01x", &v);
        EXEC(u16_eval((uint8_t)(v << 4)))
    }

    debug_logf(6, js_trace, TRACE_PDF_DUMP, nullptr,
        "literal string, in hex (UTF-16BE): %s\n", yytext);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_lit_u16()
{
    const uint8_t* ptr = (uint8_t*)yytext;
    const uint8_t* end = ptr + yyleng;

    while (ptr < end)
    {
        EXEC(u16_eval(*ptr))
        ++ptr;
    }

    debug_logf(6, js_trace, TRACE_PDF_DUMP, nullptr,
        "string, in UTF-16BE: %s\n", yytext);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_lit_u16_unescape()
{
    assert(yyleng == 2);

    // the reverse solidus behaves as a split point in this case and should be removed
    EXEC(u16_eval(literal_unescape(yytext[1])))

    debug_logf(6, js_trace, TRACE_PDF_DUMP, nullptr,
        "string, in UTF-16BE, escaped: %s\n", yytext);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_stream_open()
{
    if (obj_stream.rem_length < 0)
        return PDFRet::STREAM_NO_LENGTH;

    debug_logf(6, js_trace, TRACE_PDF_PROC, nullptr,
        "Starting %s stream, length %d\n", obj_stream.is_js ? "JavaScript" : "skipping", obj_stream.rem_length);

    return PDFRet::EOS;
}

PDFTokenizer::PDFRet PDFTokenizer::h_stream()
{
    obj_stream.rem_length -= yyleng;
    return PDFRet::EOS;
}

bool PDFTokenizer::h_stream_close()
{
    obj_stream.rem_length -= yyleng;
    if (obj_stream.rem_length <= 0)
    {
        if (YY_START == jsstream)
            yyout << '\n';
        return true;
    }

    if (YY_START == jsstream)
        ECHO;
    return false;
}

void PDFTokenizer::h_stream_length()
{
    if (!strcmp(obj_entry.key, "/Length"))
        obj_stream.rem_length = atoi(yytext);
}

void PDFTokenizer::h_ref()
{
    if (!strcmp(obj_entry.key, "/JS"))
        js_stream_refs.insert(atoi(yytext));
}

void PDFTokenizer::h_ind_obj_open()
{
    int value = atoi(yytext);
    if (js_stream_refs.count(value) > 0)
        obj_stream.is_js = true;
}

void PDFTokenizer::h_u16_start()
{
    POP();

    switch (YY_START)
    {
    case jslstr:
        POP();
        PUSH(jsstru16);
        break;
    case indobj:
        POP();
        PUSH(jsstreamu16);
        break;
    default:
        assert(false);
    }
}

void PDFTokenizer::h_u16_break()
{
    POP();
    yyless(0);

    switch (YY_START)
    {
    case indobj:
        PUSH(jsstream);
        break;
    case jslstr:
        break;
    default:
        assert(false);
    }
}

void PDFTokenizer::h_u16_hex_start()
{
    POP();

    assert(YY_START == jshstr);
    POP();
    PUSH(jshstru16);
}

void PDFTokenizer::h_u16_hex_break()
{
    POP();
    yyless(0);
    assert(YY_START == jshstr);
}

/* RFC 2781: 2.1 Encoding UTF-16 2.2, Decoding UTF-16, 4.3 Interpreting text labelled as UTF-16 */
PDFTokenizer::PDFRet PDFTokenizer::u16_eval(uint8_t byte)
{
    switch(u16_state.cur_byte)
    {
    case 0:
        u16_state.high = byte;
        u16_state.cur_byte = 1;

        break;
    case 1:
    {
        u16_state.high = (u16_state.high << 8) | byte;
        if (u16_state.high < 0xd800)
        {
            u16_to_u8(u16_state.high);
            u16_state.cur_byte = 0;
        }
        else
        {
            u16_state.high = (u16_state.high - 0xd800) * 0x400;
            u16_state.cur_byte = 2;
        }

        break;
    }
    case 2:
        u16_state.low = byte;
        u16_state.cur_byte = 3;

        break;
    case 3:
        u16_state.low = (u16_state.low << 8) | byte;
        u16_state.cur_byte = 0;

        if (u16_state.low < 0xdc00)
            return PDFRet::UNEXPECTED_SYMBOL;

        u16_state.low = u16_state.low - 0xdc00;
        u16_to_u8((u16_state.high | u16_state.low) + 0x10000);

        break;
    default:
        assert(false);
    }

    return PDFRet::EOS;
}

void PDFTokenizer::u16_to_u8(uint32_t code)
{
    assert(code <= 0x1fffff);
    std::string out;

    if (code <= 0x7f)
        out = (char)code;
    else if (code <= 0x7ff)
    {
        out += (char)(0xc0 | (code >> 6));
        out += (char)(0x80 | (code & 0x3f));
    }
    else if (code <= 0xffff)
    {
        out += (char)(0xe0 | (code >> 12));
        out += (char)(0x80 | ((code >> 6) & 0x3f));
        out += (char)(0x80 | (code & 0x3f));
    }
    else if (code <= 0x1fffff)
    {
        out += (char)(0xf0 | (code >> 18));
        out += (char)(0x80 | ((code >> 12) & 0x3f));
        out += (char)(0x80 | ((code >> 6) & 0x3f));
        out += (char)(0x80 | (code & 0x3f));
    }

    yyout << out;
}

PDFTokenizer::PDFTokenizer(std::istream& in, std::ostream& out)
    : yyFlexLexer(in, out)
{
}

PDFTokenizer::~PDFTokenizer()
{
}

PDFTokenizer::PDFRet PDFTokenizer::process()
{
    auto r = static_cast<PDFTokenizer::PDFRet>(yylex());

    if (!yy_buffer_stack or !YY_CURRENT_BUFFER_LVALUE)
        return r;

    if (YY_CURRENT_BUFFER_LVALUE->yy_buf_size > YY_BUF_SIZE)
        r = PDFTokenizer::TOKEN_TOO_LONG;

    if (r != PDFTokenizer::EOS)
        yy_flush_buffer(YY_CURRENT_BUFFER);

    return r;
}
