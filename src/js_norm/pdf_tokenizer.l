/*--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
COMMENT            %{GRP_NOT_NEWLINE}*{EOL_MARKER}

/* 7.3.2 Boolean Objects */
OBJ_BOOLEAN        true|false

/* 7.3.3 Numeric Objects */
OBJ_INT_NUM        [+-]?[0-9]{1,64}
OBJ_REL_NUM        [+-]?("."?[0-9]{1,64}|[0-9]{1,64}"."?|[0-9]{1,64}"."?[0-9]{1,64})

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
LIT_STR_BODY       [^\\\(\)]{1,64}

/* 7.3.4.3 Hexadecimal Strings */
HEX_STR_BODY       [0-9A-Fa-f]{1,64}
HEX_STR_SKIP       [^0-9A-Fa-f>]{1,64}

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
OBJ_STREAM_SKIP    {GRP_NOT_NEWLINE}{1,64}|{GRP_NEWLINE}

/* 7.3.9 Null Object */
OBJ_NULL           null

/* 7.3.10 Indirect Objects */
INDIRECT_OBJ_OPEN  {OBJ_INT_NUM}{GRP_WHITESPACE}+{OBJ_INT_NUM}{GRP_WHITESPACE}+obj

INDIRECT_OBJ_CLOSE endobj

OBJ_REFERENCE        {OBJ_INT_NUM}{GRP_WHITESPACE}+{OBJ_INT_NUM}{GRP_WHITESPACE}+R


/* Not object start, not comments */
SKIP              [^[:digit:]%]{1,64}|.
WHITESPACE        {GRP_WHITESPACE}{1,64}

/* Start conditions: INITIAL or inside dictionary, literal string, hexadecimal string */
%x indobj
%x stream
%x dictnr
%x litstr
%x hexstr
%x jslstr
%x jshstr
%x jsstream

%%

{SKIP}                                            { }
{COMMENT}                                         { }

<INITIAL>{INDIRECT_OBJ_OPEN}                      { PUSH(indobj); h_ind_obj_open(); }
<indobj>{COMMENT}                                 { }
<indobj>{WHITESPACE}                              { }
<indobj>{INDIRECT_OBJ_CLOSE}                      { POP(); h_ind_obj_close(); }

<indobj>{OBJ_STREAM_OPEN}                         { EXEC(h_stream_open()) PUSH(obj_stream.is_js ? jsstream : stream); }
<stream>{OBJ_STREAM_SKIP}                         { EXEC(h_stream()) }
<jsstream>{OBJ_STREAM_SKIP}                       { EXEC(h_stream()) ECHO; }
<stream>{OBJ_STREAM_CLOSE}                        { if (h_stream_close()) POP(); }
<jsstream>{OBJ_STREAM_CLOSE}                      { if (h_stream_close()) POP(); }

<dictnr>{OBJ_DICT_OPEN}                           { PUSH(dictnr); EXEC(h_dict_open()) }
<indobj>{OBJ_DICT_OPEN}                           { PUSH(dictnr); EXEC(h_dict_open()) }
<dictnr>{OBJ_DICT_CLOSE}                          { POP(); EXEC(h_dict_close()) }
<dictnr>{COMMENT}                                 { }
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

<jslstr>{OBJ_LIT_STR_OPEN}                        { if (!h_lit_open()) ECHO; }
<jslstr>{OBJ_LIT_STR_CLOSE}                       { if (h_lit_close()) POP(); else ECHO; }
<jslstr>{LIT_STR_ESC}                             { EXEC(h_lit_unescape()) }
<jslstr>{LIT_STR_ESC_OCT}                         { EXEC(h_lit_oct2chr()) }
<jslstr>{LIT_STR_ESC_EOL}{WHITESPACE}             { }
<jslstr>{LIT_STR_EOL}                             { ECHO; }
<jslstr>{LIT_STR_BODY}                            { ECHO; }

<jshstr>{OBJ_HEX_STR_OPEN}                        { }
<jshstr>{OBJ_HEX_STR_CLOSE}                       { POP(); }
<jshstr>{HEX_STR_BODY}                            { EXEC(h_hex_hex2chr()) }
<jshstr>{HEX_STR_SKIP}                            { }

<*><<EOF>>                                        { return PDFRet::EOS; }

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

PDFTokenizer::PDFRet PDFTokenizer::h_lit_unescape()
{
    assert(yyleng == 2);
    assert(yytext[0] == '\\');

    char c;

    // 7.3.4.2 Literal Strings, Table 3 Escape sequences in literal strings
    switch (yytext[1])
    {
    case 'n': c = '\n'; break;
    case 'r': c = '\r'; break;
    case 't': c = '\t'; break;
    case 'b': c = '\b'; break;
    case 'f': c = '\f'; break;
    case '(': c = '('; break;
    case ')': c = ')'; break;
    case '\\': c = '\\'; break;
    default: c = yytext[1];
    }

    yyout << c;

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

PDFTokenizer::PDFTokenizer(std::istream& in, std::ostream& out)
    : yyFlexLexer(in, out)
{
}

PDFTokenizer::~PDFTokenizer()
{
}

PDFTokenizer::PDFRet PDFTokenizer::process()
{
    auto r = yylex();
    return static_cast<PDFTokenizer::PDFRet>(r);
}
