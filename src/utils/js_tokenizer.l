/*--------------------------------------------------------------------------
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
// js_tokenizer.l author Oleksandr Serhiienko <oserhiie@cisco.com>
*/

/* Define JSTokenizer as yyClass */
%option yyclass="JSTokenizer"
/* Disable yywrap() generation */
%option noyywrap
/* Generate C++ scanner */
%option c++

%{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils/js_tokenizer.h"

#include <cassert>

#include "utils/js_identifier_ctx.h"
#include "utils/util_cstring.h"

#define YY_USER_ACTION                                      \
    {                                                       \
        debug_logf(5, http_trace, TRACE_JS_PROC, nullptr,   \
            "pattern #%d, sc %d\n", yy_act, YY_START);      \
                                                            \
        debug_logf(5, http_trace, TRACE_JS_DUMP, nullptr,   \
            "text '%s'\n", YYText());                       \
                                                            \
        states_push();                                      \
    }

#define EXEC(f) { auto r = (f); if (r) { BEGIN(regst); return r; } }
#define EEOF(f) { auto r = (f); if (r) { if (r != SCRIPT_CONTINUE) BEGIN(regst); return r; } }
%}

/* The following grammar was created based on ECMAScript specification */
/* source https://ecma-international.org/ecma-262/5.1/ */

/* whitespaces */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.2 */
TAB            \x9
VT             \xB
FF             \xC
SP             \x20
NBSP           \xA0
BOM            \xEF\xBB\xBF
WHITESPACES    {TAB}|{VT}|{FF}|{SP}|{NBSP}|{BOM}

/* single char escape sequences */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.8.4 */
NUL                      \x0
BS                       \x8
HT                       \x9
CHAR_ESCAPE_SEQUENCES    {NUL}|{BS}|{HT}

/* line terminators */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.3 */
LF                  \xA
CR                  \xD
LS                  \xE2\x80\xA8
PS                  \xE2\x80\xA9
LINE_TERMINATORS    {LF}|{CR}|{LS}|{PS}

/* comments */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.4 */
LINE_COMMENT_START   "//"
LINE_COMMENT_END1    [^<\xA\xD]*\xA
LINE_COMMENT_END2    [^<\xA\xD]*\xD
LINE_COMMENT_END3    [^<\xA\xD]*"<"+(?i:script)
LINE_COMMENT_END4    [^<\xA\xD]*"<"+(?i:\/script>)
LINE_COMMENT_SKIP    [^<\xA\xD]*"<"?
BLOCK_COMMENT_START  "/*"
BLOCK_COMMENT_END1   [^<*]*"*"+"/"
BLOCK_COMMENT_END2   [^<*]*"<"+(?i:script)
BLOCK_COMMENT_END3   [^<*]*"<"+(?i:\/script>)
BLOCK_COMMENT_SKIP   [^<*]*[<*]?

/* directives */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-14.1 */
USE_STRICT_DIRECTIVE    "\"use strict\""|"\'use strict\'"
USE_STRICT_DIRECTIVE_SC "\"use strict\"";*|"\'use strict\'";*

/* keywords */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.6.1.1 */
KEYWORD    break|case|debugger|in|import|protected|do|else|function|try|implements|static|instanceof|new|this|class|let|typeof|var|with|enum|private|catch|continue|default|extends|public|finally|for|if|super|yield|return|switch|throw|const|interface|void|while|delete|export|package

/* punctuators */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.7 */
CLOSING_BRACES             ")"|"]"
OPEN_BRACKET               "{"
CLOSE_BRACKET              "}"
PUNCTUATOR                 "("|"["|">="|"=="|"!="|"==="|"!=="|"."|";"|","|"<"|">"|"<="|"<<"|">>"|">>>"|"&"|"|"|"^"|"!"|"&&"|"||"|"?"|":"|"="|"+="|"-="|"*="|"%="|"<<="|">>="|">>>="|"&="|"|="|"^="|"~"
OPERATOR                   "+"|"-"|"*"|"++"|"--"|"%"
DIV_OPERATOR               "/"
DIV_ASSIGNMENT_OPERATOR    "/="

/* Unicode letter ranges (categories Lu, Ll, Lt, Lm, Lo and Nl) */
/* generated with unicode_range_generator.l */
/* UTF-8 ranges generated with https://lists.gnu.org/archive/html/help-flex/2005-01/msg00043.html */
/* the script above converts Unicode multi-byte ranges into UTF-8 encoding regex ranges since Flex doesn't support Unicode */
/* for example, the Unicode range from 0x00D1 to 0x00D6 will look like this: \xC3[\x91-\x96] */
/* just because each character in this range consists of two UTF-8 characters: \xC3 and the one of the range [\x91-\x96] */
/* using this trick it's possible to handle unicode character ranges within the Flex regular expressions */
/* i.e. the idea is to represent Unicode as a UTF-8 character sequence */
LETTER_RNG_1      [A-Z]
LETTER_RNG_2      [a-z]
LETTER_RNG_3      \xC2\xAA
LETTER_RNG_4      \xC2\xB5
LETTER_RNG_5      \xC2\xBA
LETTER_RNG_6      \xC3[\x80-\x96]
LETTER_RNG_7      \xC3[\x98-\xB6]
LETTER_RNG_8      \xC3[\xB8-\xBF]|\xCB[\x80-\x81]|[\xC4-\xCA][\x80-\xBF]
LETTER_RNG_9      \xCB[\x86-\x91]
LETTER_RNG_10     \xCB[\xA0-\xA4]
LETTER_RNG_11     \xCB\xAC
LETTER_RNG_12     \xCB\xAE
LETTER_RNG_13     \xCD[\xB0-\xB4]
LETTER_RNG_14     \xCD[\xB6-\xBD]
LETTER_RNG_15     \xCD\xBF
LETTER_RNG_16     \xCE\x86
LETTER_RNG_17     \xCE[\x88-\xBF]|\xCF[\x80-\xB5]
LETTER_RNG_18     \xCF[\xB7-\xBF]|\xD2[\x80-\x81]|[\xD0-\xD1][\x80-\xBF]
LETTER_RNG_19     \xD2[\x8A-\xBF]|\xD5[\x80-\x99]|[\xD3-\xD4][\x80-\xBF]
LETTER_RNG_20     \xD5[\xA0-\xBF]|\xD6[\x80-\x88]
LETTER_RNG_21     \xD7[\x90-\xB2]
LETTER_RNG_22     \xD8[\xA0-\xBF]|\xD9[\x80-\x8A]
LETTER_RNG_23     \xD9[\xAE-\xAF]
LETTER_RNG_24     \xD9[\xB1-\xBF]|\xDB[\x80-\x93]|\xDA[\x80-\xBF]
LETTER_RNG_25     \xDB\x95
LETTER_RNG_26     \xDB[\xA5-\xA6]
LETTER_RNG_27     \xDB[\xAE-\xAF]
LETTER_RNG_28     \xDB[\xBA-\xBC]
LETTER_RNG_29     \xDB\xBF
LETTER_RNG_30     \xDC\x90
LETTER_RNG_31     \xDC[\x92-\xAF]
LETTER_RNG_32     \xDD[\x8D-\xBF]|\xDE[\x80-\xA5]
LETTER_RNG_33     \xDE\xB1
LETTER_RNG_34     \xDF[\x8A-\xAA]
LETTER_RNG_35     \xDF[\xB4-\xB5]
LETTER_RNG_36     \xDF\xBA
LETTER_RNG_37     \xE0\xA0[\x80-\x95]
LETTER_RNG_38     \xE0\xA0\x9A
LETTER_RNG_39     \xE0\xA0\xA4
LETTER_RNG_40     \xE0\xA0\xA8
LETTER_RNG_41     \xE0\xA1[\x80-\x98]
LETTER_RNG_42     \xE0(\xA1[\xA0-\xBF]|\xA3[\x80-\x87]|\xA2[\x80-\xBF])
LETTER_RNG_43     \xE0\xA4[\x84-\xB9]
LETTER_RNG_44     \xE0\xA4\xBD
LETTER_RNG_45     \xE0\xA5\x90
LETTER_RNG_46     \xE0\xA5[\x98-\xA1]
LETTER_RNG_47     \xE0(\xA5[\xB1-\xBF]|\xA6\x80)
LETTER_RNG_48     \xE0\xA6[\x85-\xB9]
LETTER_RNG_49     \xE0\xA6\xBD
LETTER_RNG_50     \xE0\xA7\x8E
LETTER_RNG_51     \xE0\xA7[\x9C-\xA1]
LETTER_RNG_52     \xE0\xA7[\xB0-\xB1]
LETTER_RNG_53     \xE0\xA7\xBC
LETTER_RNG_54     \xE0\xA8[\x85-\xB9]
LETTER_RNG_55     \xE0\xA9[\x99-\x9E]
LETTER_RNG_56     \xE0\xA9[\xB2-\xB4]
LETTER_RNG_57     \xE0\xAA[\x85-\xB9]
LETTER_RNG_58     \xE0\xAA\xBD
LETTER_RNG_59     \xE0\xAB[\x90-\xA1]
LETTER_RNG_60     \xE0\xAB\xB9
LETTER_RNG_61     \xE0\xAC[\x85-\xB9]
LETTER_RNG_62     \xE0\xAC\xBD
LETTER_RNG_63     \xE0\xAD[\x9C-\xA1]
LETTER_RNG_64     \xE0\xAD\xB1
LETTER_RNG_65     \xE0\xAE[\x83-\xB9]
LETTER_RNG_66     \xE0\xAF\x90
LETTER_RNG_67     \xE0\xB0[\x85-\xBD]
LETTER_RNG_68     \xE0\xB1[\x98-\xA1]
LETTER_RNG_69     \xE0\xB2\x80
LETTER_RNG_70     \xE0\xB2[\x85-\xB9]
LETTER_RNG_71     \xE0\xB2\xBD
LETTER_RNG_72     \xE0\xB3[\x9E-\xA1]
LETTER_RNG_73     \xE0\xB3[\xB1-\xB2]
LETTER_RNG_74     \xE0\xB4[\x84-\xBA]
LETTER_RNG_75     \xE0\xB4\xBD
LETTER_RNG_76     \xE0\xB5\x8E
LETTER_RNG_77     \xE0\xB5[\x94-\x96]
LETTER_RNG_78     \xE0\xB5[\x9F-\xA1]
LETTER_RNG_79     \xE0\xB5[\xBA-\xBF]
LETTER_RNG_80     \xE0(\xB6[\x85-\xBF]|\xB7[\x80-\x86])
LETTER_RNG_81     \xE0\xB8[\x81-\xB0]
LETTER_RNG_82     \xE0\xB8[\xB2-\xB3]
LETTER_RNG_83     \xE0\xB9[\x80-\x86]
LETTER_RNG_84     \xE0\xBA[\x81-\xB0]
LETTER_RNG_85     \xE0\xBA[\xB2-\xB3]
LETTER_RNG_86     \xE0(\xBA[\xBD-\xBF]|\xBB[\x80-\x86])
LETTER_RNG_87     \xE0(\xBB[\x9C-\xBF]|\xBC\x80)
LETTER_RNG_88     \xE0\xBD[\x80-\xAC]
LETTER_RNG_89     \xE0\xBE[\x88-\x8C]
LETTER_RNG_90     \xE1\x80[\x80-\xAA]
LETTER_RNG_91     \xE1\x80\xBF
LETTER_RNG_92     \xE1\x81[\x90-\x95]
LETTER_RNG_93     \xE1\x81[\x9A-\x9D]
LETTER_RNG_94     \xE1\x81\xA1
LETTER_RNG_95     \xE1\x81[\xA5-\xA6]
LETTER_RNG_96     \xE1\x81[\xAE-\xB0]
LETTER_RNG_97     \xE1(\x81[\xB5-\xBF]|\x82[\x80-\x81])
LETTER_RNG_98     \xE1\x82\x8E
LETTER_RNG_99     \xE1(\x82[\xA0-\xBF]|\x83[\x80-\xBA])
LETTER_RNG_100    \xE1(\x83[\xBC-\xBF]|\x8D[\x80-\x9A]|[\x84-\x8C][\x80-\xBF])
LETTER_RNG_101    \xE1\x8E[\x80-\x8F]
LETTER_RNG_102    \xE1(\x8E[\xA0-\xBF]|\x8F[\x80-\xBD])
LETTER_RNG_103    \xE1(\x90[\x81-\xBF]|\x99[\x80-\xAC]|[\x91-\x98][\x80-\xBF])
LETTER_RNG_104    \xE1\x99[\xAF-\xBF]
LETTER_RNG_105    \xE1\x9A[\x81-\x9A]
LETTER_RNG_106    \xE1(\x9A[\xA0-\xBF]|\x9B[\x80-\xAA])
LETTER_RNG_107    \xE1(\x9B[\xAE-\xBF]|\x9C[\x80-\x91])
LETTER_RNG_108    \xE1\x9C[\xA0-\xB1]
LETTER_RNG_109    \xE1\x9D[\x80-\x91]
LETTER_RNG_110    \xE1\x9D[\xA0-\xB0]
LETTER_RNG_111    \xE1\x9E[\x80-\xB3]
LETTER_RNG_112    \xE1\x9F\x97
LETTER_RNG_113    \xE1\x9F\x9C
LETTER_RNG_114    \xE1(\xA0[\xA0-\xBF]|\xA2[\x80-\x84]|\xA1[\x80-\xBF])
LETTER_RNG_115    \xE1\xA2[\x87-\xA8]
LETTER_RNG_116    \xE1(\xA2[\xAA-\xBF]|\xA4[\x80-\x9E]|\xA3[\x80-\xBF])
LETTER_RNG_117    \xE1(\xA5[\x90-\xBF]|\xA7[\x80-\x89]|\xA6[\x80-\xBF])
LETTER_RNG_118    \xE1\xA8[\x80-\x96]
LETTER_RNG_119    \xE1(\xA8[\xA0-\xBF]|\xA9[\x80-\x94])
LETTER_RNG_120    \xE1\xAA\xA7
LETTER_RNG_121    \xE1\xAC[\x85-\xB3]
LETTER_RNG_122    \xE1\xAD[\x85-\x8B]
LETTER_RNG_123    \xE1\xAE[\x83-\xA0]
LETTER_RNG_124    \xE1\xAE[\xAE-\xAF]
LETTER_RNG_125    \xE1(\xAE[\xBA-\xBF]|\xAF[\x80-\xA5])
LETTER_RNG_126    \xE1\xB0[\x80-\xA3]
LETTER_RNG_127    \xE1\xB1[\x8D-\x8F]
LETTER_RNG_128    \xE1\xB1[\x9A-\xBD]
LETTER_RNG_129    \xE1\xB2[\x80-\xBF]
LETTER_RNG_130    \xE1\xB3[\xA9-\xAC]
LETTER_RNG_131    \xE1\xB3[\xAE-\xB3]
LETTER_RNG_132    \xE1\xB3[\xB5-\xB6]
LETTER_RNG_133    \xE1(\xB3[\xBA-\xBF]|[\xB4-\xB6][\x80-\xBF])
LETTER_RNG_134    \xE1(\xBE[\x80-\xBC]|[\xB8-\xBD][\x80-\xBF])
LETTER_RNG_135    \xE1\xBE\xBE
LETTER_RNG_136    \xE1\xBF[\x82-\x8C]
LETTER_RNG_137    \xE1\xBF[\x90-\x9B]
LETTER_RNG_138    \xE1\xBF[\xA0-\xAC]
LETTER_RNG_139    \xE1\xBF[\xB2-\xBC]
LETTER_RNG_140    \xE2\x81\xB1
LETTER_RNG_141    \xE2\x81\xBF
LETTER_RNG_142    \xE2\x82[\x90-\x9C]
LETTER_RNG_143    \xE2\x84\x82
LETTER_RNG_144    \xE2\x84\x87
LETTER_RNG_145    \xE2\x84[\x8A-\x93]
LETTER_RNG_146    \xE2\x84\x95
LETTER_RNG_147    \xE2\x84[\x99-\x9D]
LETTER_RNG_148    \xE2\x84\xA4
LETTER_RNG_149    \xE2\x84\xA6
LETTER_RNG_150    \xE2\x84\xA8
LETTER_RNG_151    \xE2\x84[\xAA-\xAD]
LETTER_RNG_152    \xE2\x84[\xAF-\xB9]
LETTER_RNG_153    \xE2\x84[\xBC-\xBF]
LETTER_RNG_154    \xE2\x85[\x85-\x89]
LETTER_RNG_155    \xE2\x85\x8E
LETTER_RNG_156    \xE2(\x85[\xA0-\xBF]|\x86[\x80-\x88])
LETTER_RNG_157    \xE2(\xB3[\x80-\xA4]|[\xB0-\xB2][\x80-\xBF])
LETTER_RNG_158    \xE2\xB3[\xAB-\xAE]
LETTER_RNG_159    \xE2\xB3[\xB2-\xB3]
LETTER_RNG_160    \xE2(\xB5[\x80-\xAF]|\xB4[\x80-\xBF])
LETTER_RNG_161    \xE2(\xB7[\x80-\x9E]|\xB6[\x80-\xBF])
LETTER_RNG_162    \xE2\xB8\xAF
LETTER_RNG_163    \xE3\x80[\x85-\x87]
LETTER_RNG_164    \xE3\x80[\xA1-\xA9]
LETTER_RNG_165    \xE3\x80[\xB1-\xB5]
LETTER_RNG_166    \xE3\x80[\xB8-\xBC]
LETTER_RNG_167    \xE3(\x81[\x81-\xBF]|\x82[\x80-\x96])
LETTER_RNG_168    \xE3\x82[\x9D-\x9F]
LETTER_RNG_169    \xE3(\x82[\xA1-\xBF]|\x83[\x80-\xBA])
LETTER_RNG_170    \xE3(\x83[\xBC-\xBF]|\x86[\x80-\x8E]|[\x84-\x85][\x80-\xBF])
LETTER_RNG_171    \xE3\x86[\xA0-\xBF]
LETTER_RNG_172    \xE3\x87[\xB0-\xBF]
LETTER_RNG_173    (\xE3[\x90-\xBF]|\xE4[\x80-\xB6])[\x80-\xBF]
LETTER_RNG_174    \xEA\x92[\x80-\x8C]|(\xE4[\xB8-\xBF]|\xEA[\x80-\x91]|[\xE5-\xE9][\x80-\xBF])[\x80-\xBF]
LETTER_RNG_175    \xEA\x93[\x90-\xBD]
LETTER_RNG_176    \xEA(\x98[\x80-\x8C]|[\x94-\x97][\x80-\xBF])
LETTER_RNG_177    \xEA\x98[\x90-\x9F]
LETTER_RNG_178    \xEA(\x98[\xAA-\xBF]|\x99[\x80-\xAE])
LETTER_RNG_179    \xEA(\x99\xBF|\x9A[\x80-\x9D])
LETTER_RNG_180    \xEA(\x9A[\xA0-\xBF]|\x9B[\x80-\xAF])
LETTER_RNG_181    \xEA\x9C[\x97-\x9F]
LETTER_RNG_182    \xEA(\x9C[\xA2-\xBF]|\x9E[\x80-\x88]|\x9D[\x80-\xBF])
LETTER_RNG_183    \xEA(\x9E[\x8B-\xBF]|\xA0[\x80-\x81]|\x9F[\x80-\xBF])
LETTER_RNG_184    \xEA\xA0[\x83-\x85]
LETTER_RNG_185    \xEA\xA0[\x87-\x8A]
LETTER_RNG_186    \xEA\xA0[\x8C-\xA2]
LETTER_RNG_187    \xEA\xA1[\x80-\xB3]
LETTER_RNG_188    \xEA\xA2[\x82-\xB3]
LETTER_RNG_189    \xEA\xA3[\xB2-\xB7]
LETTER_RNG_190    \xEA\xA3\xBB
LETTER_RNG_191    \xEA\xA3[\xBD-\xBE]
LETTER_RNG_192    \xEA\xA4[\x8A-\xA5]
LETTER_RNG_193    \xEA(\xA4[\xB0-\xBF]|\xA5[\x80-\x86])
LETTER_RNG_194    \xEA\xA5[\xA0-\xBC]
LETTER_RNG_195    \xEA\xA6[\x84-\xB2]
LETTER_RNG_196    \xEA\xA7\x8F
LETTER_RNG_197    \xEA\xA7[\xA0-\xA4]
LETTER_RNG_198    \xEA\xA7[\xA6-\xAF]
LETTER_RNG_199    \xEA(\xA7[\xBA-\xBF]|\xA8[\x80-\xA8])
LETTER_RNG_200    \xEA\xA9[\x80-\x82]
LETTER_RNG_201    \xEA\xA9[\x84-\x8B]
LETTER_RNG_202    \xEA\xA9[\xA0-\xB6]
LETTER_RNG_203    \xEA\xA9\xBA
LETTER_RNG_204    \xEA(\xA9[\xBE-\xBF]|\xAA[\x80-\xAF])
LETTER_RNG_205    \xEA\xAA\xB1
LETTER_RNG_206    \xEA\xAA[\xB5-\xB6]
LETTER_RNG_207    \xEA\xAA[\xB9-\xBD]
LETTER_RNG_208    \xEA\xAB\x80
LETTER_RNG_209    \xEA\xAB[\x82-\x9D]
LETTER_RNG_210    \xEA\xAB[\xA0-\xAA]
LETTER_RNG_211    \xEA\xAB[\xB2-\xB4]
LETTER_RNG_212    \xEA(\xAC[\x81-\xBF]|\xAD[\x80-\x9A])
LETTER_RNG_213    \xEA\xAD[\x9C-\xA9]
LETTER_RNG_214    \xEA(\xAD[\xB0-\xBF]|\xAF[\x80-\xA2]|\xAE[\x80-\xBF])
LETTER_RNG_215    \xED\x9F[\x80-\xBB]|(\xEA[\xB0-\xBF]|\xED[\x80-\x9E]|[\xEB-\xEC][\x80-\xBF])[\x80-\xBF]
LETTER_RNG_216    \xEF(\xAC[\x80-\x9D]|[\xA4-\xAB][\x80-\xBF])
LETTER_RNG_217    \xEF\xAC[\x9F-\xA8]
LETTER_RNG_218    \xEF(\xAC[\xAA-\xBF]|\xAE[\x80-\xB1]|\xAD[\x80-\xBF])
LETTER_RNG_219    \xEF(\xAF[\x93-\xBF]|\xB4[\x80-\xBD]|[\xB0-\xB3][\x80-\xBF])
LETTER_RNG_220    \xEF(\xB5[\x90-\xBF]|\xB7[\x80-\xBB]|\xB6[\x80-\xBF])
LETTER_RNG_221    \xEF(\xB9[\xB0-\xBF]|\xBB[\x80-\xBC]|\xBA[\x80-\xBF])
LETTER_RNG_222    \xEF\xBC[\xA1-\xBA]
LETTER_RNG_223    \xEF\xBD[\x81-\x9A]
LETTER_RNG_224    \xEF(\xBD[\xA6-\xBF]|\xBF[\x80-\x9C]|\xBE[\x80-\xBF])
LETTER_RNG_225    \xF0\x90(\x83[\x80-\xBA]|[\x80-\x82][\x80-\xBF])
LETTER_RNG_226    \xF0\x90\x85[\x80-\xB4]
LETTER_RNG_227    \xF0\x90(\x8B[\x80-\x90]|\x8A[\x80-\xBF])
LETTER_RNG_228    \xF0\x90\x8C[\x80-\x9F]
LETTER_RNG_229    \xF0\x90(\x8C[\xAD-\xBF]|\x8D[\x80-\xB5])
LETTER_RNG_230    \xF0\x90\x8E[\x80-\x9D]
LETTER_RNG_231    \xF0\x90(\x8E[\xA0-\xBF]|\x8F[\x80-\x8F])
LETTER_RNG_232    \xF0\x90(\x8F[\x91-\xBF]|\x92[\x80-\x9D]|[\x90-\x91][\x80-\xBF])
LETTER_RNG_233    \xF0\x90(\x92[\xB0-\xBF]|\x95[\x80-\xA3]|[\x93-\x94][\x80-\xBF])
LETTER_RNG_234    \xF0\x90(\xA1[\x80-\x95]|[\x98-\xA0][\x80-\xBF])
LETTER_RNG_235    \xF0\x90\xA1[\xA0-\xB6]
LETTER_RNG_236    \xF0\x90\xA2[\x80-\x9E]
LETTER_RNG_237    \xF0\x90\xA3[\xA0-\xB5]
LETTER_RNG_238    \xF0\x90\xA4[\x80-\x95]
LETTER_RNG_239    \xF0\x90\xA4[\xA0-\xB9]
LETTER_RNG_240    \xF0\x90\xA6[\x80-\xB7]
LETTER_RNG_241    \xF0\x90\xA6[\xBE-\xBF]
LETTER_RNG_242    \xF0\x90\xA8\x80
LETTER_RNG_243    \xF0\x90\xA8[\x90-\xB5]
LETTER_RNG_244    \xF0\x90\xA9[\xA0-\xBC]
LETTER_RNG_245    \xF0\x90\xAA[\x80-\x9C]
LETTER_RNG_246    \xF0\x90\xAB[\x80-\x87]
LETTER_RNG_247    \xF0\x90\xAB[\x89-\xA4]
LETTER_RNG_248    \xF0\x90\xAC[\x80-\xB5]
LETTER_RNG_249    \xF0\x90\xAD[\x80-\x95]
LETTER_RNG_250    \xF0\x90\xAD[\xA0-\xB2]
LETTER_RNG_251    \xF0\x90\xAE[\x80-\x91]
LETTER_RNG_252    \xF0\x90(\xB3[\x80-\xB2]|[\xB0-\xB2][\x80-\xBF])
LETTER_RNG_253    \xF0\x90\xB4[\x80-\xA3]
LETTER_RNG_254    \xF0\x90\xBA[\x80-\xA9]
LETTER_RNG_255    \xF0\x90(\xBA[\xB0-\xBF]|\xBC[\x80-\x9C]|\xBB[\x80-\xBF])
LETTER_RNG_256    \xF0\x90(\xBC[\xA7-\xBF]|\xBD[\x80-\x85])
LETTER_RNG_257    \xF0\x90(\xBE[\xB0-\xBF]|\xBF[\x80-\x84])
LETTER_RNG_258    \xF0\x90\xBF[\xA0-\xB6]
LETTER_RNG_259    \xF0\x91\x80[\x83-\xB7]
LETTER_RNG_260    \xF0\x91\x82[\x83-\xAF]
LETTER_RNG_261    \xF0\x91\x83[\x90-\xA8]
LETTER_RNG_262    \xF0\x91\x84[\x83-\xA6]
LETTER_RNG_263    \xF0\x91\x85\x84
LETTER_RNG_264    \xF0\x91\x85[\x87-\xB2]
LETTER_RNG_265    \xF0\x91\x85\xB6
LETTER_RNG_266    \xF0\x91\x86[\x83-\xB2]
LETTER_RNG_267    \xF0\x91\x87[\x81-\x84]
LETTER_RNG_268    \xF0\x91\x87\x9A
LETTER_RNG_269    \xF0\x91\x87\x9C
LETTER_RNG_270    \xF0\x91\x88[\x80-\xAB]
LETTER_RNG_271    \xF0\x91\x8A[\x80-\xA8]
LETTER_RNG_272    \xF0\x91(\x8A[\xB0-\xBF]|\x8B[\x80-\x9E])
LETTER_RNG_273    \xF0\x91\x8C[\x85-\xB9]
LETTER_RNG_274    \xF0\x91\x8C\xBD
LETTER_RNG_275    \xF0\x91\x8D\x90
LETTER_RNG_276    \xF0\x91\x8D[\x9D-\xA1]
LETTER_RNG_277    \xF0\x91\x90[\x80-\xB4]
LETTER_RNG_278    \xF0\x91\x91[\x87-\x8A]
LETTER_RNG_279    \xF0\x91(\x91[\x9F-\xBF]|\x92[\x80-\xAF])
LETTER_RNG_280    \xF0\x91\x93[\x84-\x85]
LETTER_RNG_281    \xF0\x91\x93\x87
LETTER_RNG_282    \xF0\x91\x96[\x80-\xAE]
LETTER_RNG_283    \xF0\x91\x97[\x98-\x9B]
LETTER_RNG_284    \xF0\x91\x98[\x80-\xAF]
LETTER_RNG_285    \xF0\x91\x99\x84
LETTER_RNG_286    \xF0\x91\x9A[\x80-\xAA]
LETTER_RNG_287    \xF0\x91\x9A\xB8
LETTER_RNG_288    \xF0\x91\x9C[\x80-\x9A]
LETTER_RNG_289    \xF0\x91\xA0[\x80-\xAB]
LETTER_RNG_290    \xF0\x91(\xA2[\xA0-\xBF]|\xA3[\x80-\x9F])
LETTER_RNG_291    \xF0\x91(\xA3\xBF|\xA4[\x80-\xAF])
LETTER_RNG_292    \xF0\x91\xA4\xBF
LETTER_RNG_293    \xF0\x91\xA5\x81
LETTER_RNG_294    \xF0\x91(\xA6[\xA0-\xBF]|\xA7[\x80-\x90])
LETTER_RNG_295    \xF0\x91\xA7\xA1
LETTER_RNG_296    \xF0\x91\xA7\xA3
LETTER_RNG_297    \xF0\x91\xA8\x80
LETTER_RNG_298    \xF0\x91\xA8[\x8B-\xB2]
LETTER_RNG_299    \xF0\x91\xA8\xBA
LETTER_RNG_300    \xF0\x91\xA9\x90
LETTER_RNG_301    \xF0\x91(\xA9[\x9C-\xBF]|\xAA[\x80-\x89])
LETTER_RNG_302    \xF0\x91\xAA\x9D
LETTER_RNG_303    \xF0\x91(\xB0[\x80-\xAE]|[\xAB-\xAF][\x80-\xBF])
LETTER_RNG_304    \xF0\x91\xB1\x80
LETTER_RNG_305    \xF0\x91(\xB1[\xB2-\xBF]|\xB2[\x80-\x8F])
LETTER_RNG_306    \xF0\x91\xB4[\x80-\xB0]
LETTER_RNG_307    \xF0\x91\xB5\x86
LETTER_RNG_308    \xF0\x91(\xB5[\xA0-\xBF]|\xB6[\x80-\x89])
LETTER_RNG_309    \xF0\x91\xB6\x98
LETTER_RNG_310    \xF0\x91\xBB[\xA0-\xB2]
LETTER_RNG_311    \xF0\x91\xBE\xB0
LETTER_RNG_312    \xF0\x92(\x91[\x80-\xAE]|[\x80-\x90][\x80-\xBF])
LETTER_RNG_313    \xF0(\x93\x90[\x80-\xAE]|(\x92[\x92-\xBF]|\x93[\x80-\x8F])[\x80-\xBF])
LETTER_RNG_314    \xF0(\x96\xA9[\x80-\x9E]|(\x94[\x90-\xBF]|\x96[\x80-\xA8]|\x95[\x80-\xBF])[\x80-\xBF])
LETTER_RNG_315    \xF0\x96\xAB[\x90-\xAD]
LETTER_RNG_316    \xF0\x96\xAC[\x80-\xAF]
LETTER_RNG_317    \xF0\x96\xAD[\x80-\x83]
LETTER_RNG_318    \xF0\x96(\xAD[\xA3-\xBF]|[\xAE-\xB9][\x80-\xBF])
LETTER_RNG_319    \xF0\x96(\xBD[\x80-\x8A]|\xBC[\x80-\xBF])
LETTER_RNG_320    \xF0\x96\xBD\x90
LETTER_RNG_321    \xF0\x96(\xBE[\x93-\xBF]|\xBF[\x80-\xA1])
LETTER_RNG_322    \xF0\x96\xBF\xA3
LETTER_RNG_323    \xF0(\x9B\xB2[\x80-\x99]|(\x9B[\x80-\xB1]|[\x97-\x9A][\x80-\xBF])[\x80-\xBF])
LETTER_RNG_324    \xF0\x9D(\x9B\x80|[\x90-\x9A][\x80-\xBF])
LETTER_RNG_325    \xF0\x9D\x9B[\x82-\x9A]
LETTER_RNG_326    \xF0\x9D\x9B[\x9C-\xBA]
LETTER_RNG_327    \xF0\x9D(\x9B[\xBC-\xBF]|\x9C[\x80-\x94])
LETTER_RNG_328    \xF0\x9D\x9C[\x96-\xB4]
LETTER_RNG_329    \xF0\x9D(\x9C[\xB6-\xBF]|\x9D[\x80-\x8E])
LETTER_RNG_330    \xF0\x9D\x9D[\x90-\xAE]
LETTER_RNG_331    \xF0\x9D(\x9D[\xB0-\xBF]|\x9E[\x80-\x88])
LETTER_RNG_332    \xF0\x9D\x9E[\x8A-\xA8]
LETTER_RNG_333    \xF0\x9D(\x9E[\xAA-\xBF]|\x9F[\x80-\x82])
LETTER_RNG_334    \xF0\x9D\x9F[\x84-\x8B]
LETTER_RNG_335    \xF0\x9E\x84[\x80-\xAC]
LETTER_RNG_336    \xF0\x9E\x84[\xB7-\xBD]
LETTER_RNG_337    \xF0\x9E\x85\x8E
LETTER_RNG_338    \xF0\x9E\x8B[\x80-\xAB]
LETTER_RNG_339    \xF0\x9E(\xA3[\x80-\x84]|[\xA0-\xA2][\x80-\xBF])
LETTER_RNG_340    \xF0\x9E(\xA5[\x80-\x83]|\xA4[\x80-\xBF])
LETTER_RNG_341    \xF0\x9E\xA5\x8B
LETTER_RNG_342    \xF0\x9E(\xBA[\x80-\xBB]|[\xB8-\xB9][\x80-\xBF])
LETTER_RNG_343    \xF0(\xB1\x8D[\x80-\x8A]|(\xB1[\x80-\x8C]|[\xA0-\xB0][\x80-\xBF])[\x80-\xBF])

LETTER_GROUP_1     {LETTER_RNG_1}|{LETTER_RNG_2}|{LETTER_RNG_3}|{LETTER_RNG_4}|{LETTER_RNG_5}|{LETTER_RNG_6}|{LETTER_RNG_7}|{LETTER_RNG_8}|{LETTER_RNG_9}|{LETTER_RNG_10}
LETTER_GROUP_2     {LETTER_GROUP_1}|{LETTER_RNG_11}|{LETTER_RNG_12}|{LETTER_RNG_13}|{LETTER_RNG_14}|{LETTER_RNG_15}|{LETTER_RNG_16}|{LETTER_RNG_17}|{LETTER_RNG_18}|{LETTER_RNG_19}
LETTER_GROUP_3     {LETTER_GROUP_2}|{LETTER_RNG_20}|{LETTER_RNG_21}|{LETTER_RNG_22}|{LETTER_RNG_23}|{LETTER_RNG_24}|{LETTER_RNG_25}|{LETTER_RNG_26}|{LETTER_RNG_27}|{LETTER_RNG_28}
LETTER_GROUP_4     {LETTER_GROUP_3}|{LETTER_RNG_29}|{LETTER_RNG_30}|{LETTER_RNG_31}|{LETTER_RNG_32}|{LETTER_RNG_33}|{LETTER_RNG_34}|{LETTER_RNG_35}|{LETTER_RNG_36}|{LETTER_RNG_37}
LETTER_GROUP_5     {LETTER_GROUP_4}|{LETTER_RNG_38}|{LETTER_RNG_39}|{LETTER_RNG_40}|{LETTER_RNG_41}|{LETTER_RNG_42}|{LETTER_RNG_43}|{LETTER_RNG_44}|{LETTER_RNG_45}|{LETTER_RNG_46}
LETTER_GROUP_6     {LETTER_GROUP_5}|{LETTER_RNG_47}|{LETTER_RNG_48}|{LETTER_RNG_49}|{LETTER_RNG_50}|{LETTER_RNG_51}|{LETTER_RNG_52}|{LETTER_RNG_53}|{LETTER_RNG_54}|{LETTER_RNG_55}
LETTER_GROUP_7     {LETTER_GROUP_6}|{LETTER_RNG_56}|{LETTER_RNG_57}|{LETTER_RNG_58}|{LETTER_RNG_59}|{LETTER_RNG_60}|{LETTER_RNG_61}|{LETTER_RNG_62}|{LETTER_RNG_63}|{LETTER_RNG_64}
LETTER_GROUP_8     {LETTER_GROUP_7}|{LETTER_RNG_65}|{LETTER_RNG_66}|{LETTER_RNG_67}|{LETTER_RNG_68}|{LETTER_RNG_69}|{LETTER_RNG_70}|{LETTER_RNG_71}|{LETTER_RNG_72}|{LETTER_RNG_73}
LETTER_GROUP_9     {LETTER_GROUP_8}|{LETTER_RNG_74}|{LETTER_RNG_75}|{LETTER_RNG_76}|{LETTER_RNG_77}|{LETTER_RNG_78}|{LETTER_RNG_79}|{LETTER_RNG_80}|{LETTER_RNG_81}|{LETTER_RNG_82}
LETTER_GROUP_10    {LETTER_GROUP_9}|{LETTER_RNG_83}|{LETTER_RNG_84}|{LETTER_RNG_85}|{LETTER_RNG_86}|{LETTER_RNG_87}|{LETTER_RNG_88}|{LETTER_RNG_89}|{LETTER_RNG_90}|{LETTER_RNG_91}
LETTER_GROUP_11    {LETTER_GROUP_10}|{LETTER_RNG_92}|{LETTER_RNG_93}|{LETTER_RNG_94}|{LETTER_RNG_95}|{LETTER_RNG_96}|{LETTER_RNG_97}|{LETTER_RNG_98}|{LETTER_RNG_99}|{LETTER_RNG_100}
LETTER_GROUP_12    {LETTER_GROUP_11}|{LETTER_RNG_101}|{LETTER_RNG_102}|{LETTER_RNG_103}|{LETTER_RNG_104}|{LETTER_RNG_105}|{LETTER_RNG_106}|{LETTER_RNG_107}|{LETTER_RNG_108}|{LETTER_RNG_109}
LETTER_GROUP_13    {LETTER_GROUP_12}|{LETTER_RNG_110}|{LETTER_RNG_111}|{LETTER_RNG_112}|{LETTER_RNG_113}|{LETTER_RNG_114}|{LETTER_RNG_115}|{LETTER_RNG_116}|{LETTER_RNG_117}|{LETTER_RNG_118}
LETTER_GROUP_14    {LETTER_GROUP_13}|{LETTER_RNG_119}|{LETTER_RNG_120}|{LETTER_RNG_121}|{LETTER_RNG_122}|{LETTER_RNG_123}|{LETTER_RNG_124}|{LETTER_RNG_125}|{LETTER_RNG_126}|{LETTER_RNG_127}
LETTER_GROUP_15    {LETTER_GROUP_14}|{LETTER_RNG_128}|{LETTER_RNG_129}|{LETTER_RNG_130}|{LETTER_RNG_131}|{LETTER_RNG_132}|{LETTER_RNG_133}|{LETTER_RNG_134}|{LETTER_RNG_135}|{LETTER_RNG_136}
LETTER_GROUP_16    {LETTER_GROUP_15}|{LETTER_RNG_137}|{LETTER_RNG_138}|{LETTER_RNG_139}|{LETTER_RNG_140}|{LETTER_RNG_141}|{LETTER_RNG_142}|{LETTER_RNG_143}|{LETTER_RNG_144}|{LETTER_RNG_145}
LETTER_GROUP_17    {LETTER_GROUP_15}|{LETTER_RNG_146}|{LETTER_RNG_147}|{LETTER_RNG_148}|{LETTER_RNG_149}|{LETTER_RNG_150}|{LETTER_RNG_151}|{LETTER_RNG_152}|{LETTER_RNG_153}|{LETTER_RNG_154}
LETTER_GROUP_18    {LETTER_GROUP_17}|{LETTER_RNG_155}|{LETTER_RNG_156}|{LETTER_RNG_157}|{LETTER_RNG_158}|{LETTER_RNG_159}|{LETTER_RNG_160}|{LETTER_RNG_161}|{LETTER_RNG_162}|{LETTER_RNG_163}
LETTER_GROUP_19    {LETTER_GROUP_18}|{LETTER_RNG_164}|{LETTER_RNG_165}|{LETTER_RNG_166}|{LETTER_RNG_167}|{LETTER_RNG_168}|{LETTER_RNG_169}|{LETTER_RNG_170}|{LETTER_RNG_171}|{LETTER_RNG_172}
LETTER_GROUP_20    {LETTER_GROUP_19}|{LETTER_RNG_173}|{LETTER_RNG_174}|{LETTER_RNG_175}|{LETTER_RNG_176}|{LETTER_RNG_177}|{LETTER_RNG_178}|{LETTER_RNG_179}|{LETTER_RNG_180}|{LETTER_RNG_181}
LETTER_GROUP_21    {LETTER_GROUP_20}|{LETTER_RNG_182}|{LETTER_RNG_183}|{LETTER_RNG_184}|{LETTER_RNG_185}|{LETTER_RNG_186}|{LETTER_RNG_187}|{LETTER_RNG_188}|{LETTER_RNG_189}|{LETTER_RNG_190}
LETTER_GROUP_22    {LETTER_GROUP_21}|{LETTER_RNG_191}|{LETTER_RNG_192}|{LETTER_RNG_193}|{LETTER_RNG_194}|{LETTER_RNG_195}|{LETTER_RNG_196}|{LETTER_RNG_197}|{LETTER_RNG_198}|{LETTER_RNG_199}
LETTER_GROUP_23    {LETTER_GROUP_22}|{LETTER_RNG_200}|{LETTER_RNG_201}|{LETTER_RNG_202}|{LETTER_RNG_203}|{LETTER_RNG_204}|{LETTER_RNG_205}|{LETTER_RNG_206}|{LETTER_RNG_207}|{LETTER_RNG_208}
LETTER_GROUP_24    {LETTER_GROUP_23}|{LETTER_RNG_209}|{LETTER_RNG_210}|{LETTER_RNG_211}|{LETTER_RNG_212}|{LETTER_RNG_213}|{LETTER_RNG_214}|{LETTER_RNG_215}|{LETTER_RNG_216}|{LETTER_RNG_217}
LETTER_GROUP_25    {LETTER_GROUP_24}|{LETTER_RNG_218}|{LETTER_RNG_219}|{LETTER_RNG_220}|{LETTER_RNG_221}|{LETTER_RNG_222}|{LETTER_RNG_223}|{LETTER_RNG_224}|{LETTER_RNG_225}|{LETTER_RNG_226}
LETTER_GROUP_26    {LETTER_GROUP_25}|{LETTER_RNG_227}|{LETTER_RNG_228}|{LETTER_RNG_229}|{LETTER_RNG_230}|{LETTER_RNG_231}|{LETTER_RNG_232}|{LETTER_RNG_233}|{LETTER_RNG_234}|{LETTER_RNG_235}
LETTER_GROUP_27    {LETTER_GROUP_26}|{LETTER_RNG_236}|{LETTER_RNG_237}|{LETTER_RNG_238}|{LETTER_RNG_239}|{LETTER_RNG_240}|{LETTER_RNG_241}|{LETTER_RNG_242}|{LETTER_RNG_243}|{LETTER_RNG_244}
LETTER_GROUP_28    {LETTER_GROUP_27}|{LETTER_RNG_245}|{LETTER_RNG_246}|{LETTER_RNG_247}|{LETTER_RNG_248}|{LETTER_RNG_249}|{LETTER_RNG_250}|{LETTER_RNG_251}|{LETTER_RNG_252}|{LETTER_RNG_253}
LETTER_GROUP_29    {LETTER_GROUP_28}|{LETTER_RNG_254}|{LETTER_RNG_255}|{LETTER_RNG_256}|{LETTER_RNG_257}|{LETTER_RNG_258}|{LETTER_RNG_259}|{LETTER_RNG_260}|{LETTER_RNG_261}|{LETTER_RNG_262}
LETTER_GROUP_30    {LETTER_GROUP_29}|{LETTER_RNG_263}|{LETTER_RNG_264}|{LETTER_RNG_265}|{LETTER_RNG_266}|{LETTER_RNG_267}|{LETTER_RNG_268}|{LETTER_RNG_269}|{LETTER_RNG_270}|{LETTER_RNG_271}
LETTER_GROUP_31    {LETTER_GROUP_30}|{LETTER_RNG_272}|{LETTER_RNG_273}|{LETTER_RNG_274}|{LETTER_RNG_275}|{LETTER_RNG_276}|{LETTER_RNG_277}|{LETTER_RNG_278}|{LETTER_RNG_279}|{LETTER_RNG_280}
LETTER_GROUP_32    {LETTER_GROUP_31}|{LETTER_RNG_281}|{LETTER_RNG_282}|{LETTER_RNG_283}|{LETTER_RNG_284}|{LETTER_RNG_285}|{LETTER_RNG_286}|{LETTER_RNG_287}|{LETTER_RNG_288}|{LETTER_RNG_289}
LETTER_GROUP_33    {LETTER_GROUP_32}|{LETTER_RNG_290}|{LETTER_RNG_291}|{LETTER_RNG_292}|{LETTER_RNG_293}|{LETTER_RNG_294}|{LETTER_RNG_295}|{LETTER_RNG_296}|{LETTER_RNG_297}|{LETTER_RNG_298}
LETTER_GROUP_34    {LETTER_GROUP_33}|{LETTER_RNG_299}|{LETTER_RNG_300}|{LETTER_RNG_301}|{LETTER_RNG_302}|{LETTER_RNG_303}|{LETTER_RNG_304}|{LETTER_RNG_305}|{LETTER_RNG_306}|{LETTER_RNG_307}
LETTER_GROUP_35    {LETTER_GROUP_34}|{LETTER_RNG_308}|{LETTER_RNG_309}|{LETTER_RNG_310}|{LETTER_RNG_311}|{LETTER_RNG_312}|{LETTER_RNG_313}|{LETTER_RNG_314}|{LETTER_RNG_315}|{LETTER_RNG_316}
LETTER_GROUP_36    {LETTER_GROUP_35}|{LETTER_RNG_317}|{LETTER_RNG_318}|{LETTER_RNG_319}|{LETTER_RNG_320}|{LETTER_RNG_321}|{LETTER_RNG_322}|{LETTER_RNG_323}|{LETTER_RNG_324}|{LETTER_RNG_325}
LETTER_GROUP_37    {LETTER_GROUP_36}|{LETTER_RNG_326}|{LETTER_RNG_327}|{LETTER_RNG_328}|{LETTER_RNG_329}|{LETTER_RNG_330}|{LETTER_RNG_331}|{LETTER_RNG_332}|{LETTER_RNG_333}|{LETTER_RNG_334}
LETTER_GROUP_38    {LETTER_GROUP_37}|{LETTER_RNG_335}|{LETTER_RNG_336}|{LETTER_RNG_337}|{LETTER_RNG_338}|{LETTER_RNG_339}|{LETTER_RNG_340}|{LETTER_RNG_341}|{LETTER_RNG_342}|{LETTER_RNG_343}

LETTER_G_GROUP_1    {LETTER_GROUP_1}|{LETTER_GROUP_2}|{LETTER_GROUP_3}|{LETTER_GROUP_4}|{LETTER_GROUP_5}|{LETTER_GROUP_6}|{LETTER_GROUP_7}|{LETTER_GROUP_8}|{LETTER_GROUP_9}|{LETTER_GROUP_10}
LETTER_G_GROUP_2    {LETTER_G_GROUP_1}|{LETTER_GROUP_11}|{LETTER_GROUP_12}|{LETTER_GROUP_13}|{LETTER_GROUP_14}|{LETTER_GROUP_15}|{LETTER_GROUP_16}|{LETTER_GROUP_17}|{LETTER_GROUP_18}|{LETTER_GROUP_19}
LETTER_G_GROUP_3    {LETTER_G_GROUP_2}|{LETTER_GROUP_20}|{LETTER_GROUP_21}|{LETTER_GROUP_22}|{LETTER_GROUP_23}|{LETTER_GROUP_24}|{LETTER_GROUP_25}|{LETTER_GROUP_26}|{LETTER_GROUP_27}|{LETTER_GROUP_28}
LETTER_G_GROUP_4    {LETTER_G_GROUP_3}|{LETTER_GROUP_29}|{LETTER_GROUP_30}|{LETTER_GROUP_31}|{LETTER_GROUP_32}|{LETTER_GROUP_33}|{LETTER_GROUP_34}|{LETTER_GROUP_35}|{LETTER_GROUP_36}|{LETTER_GROUP_37}
LETTER_G_GROUP_5    {LETTER_G_GROUP_4}|{LETTER_GROUP_38}

UNICODE_LETTER    {LETTER_G_GROUP_1}|{LETTER_G_GROUP_2}|{LETTER_G_GROUP_3}|{LETTER_G_GROUP_4}|{LETTER_G_GROUP_5}

/* Unicode digit ranges (category Nd) */
/* generated with unicode_range_generator.l */
/* UTF-8 ranges generated with https://lists.gnu.org/archive/html/help-flex/2005-01/msg00043.html */
DIGIT_RNG_1     [0-9]
DIGIT_RNG_2     \xD9[\xA0-\xA9]
DIGIT_RNG_3     \xDB[\xB0-\xB9]
DIGIT_RNG_4     \xDF[\x80-\x89]
DIGIT_RNG_5     \xE0\xA5[\xA6-\xAF]
DIGIT_RNG_6     \xE0\xA7[\xA6-\xAF]
DIGIT_RNG_7     \xE0\xA9[\xA6-\xAF]
DIGIT_RNG_8     \xE0\xAB[\xA6-\xAF]
DIGIT_RNG_9     \xE0\xAD[\xA6-\xAF]
DIGIT_RNG_10    \xE0\xAF[\xA6-\xAF]
DIGIT_RNG_11    \xE0\xB1[\xA6-\xAF]
DIGIT_RNG_12    \xE0\xB3[\xA6-\xAF]
DIGIT_RNG_13    \xE0\xB5[\xA6-\xAF]
DIGIT_RNG_14    \xE0\xB7[\xA6-\xAF]
DIGIT_RNG_15    \xE0\xB9[\x90-\x99]
DIGIT_RNG_16    \xE0\xBB[\x90-\x99]
DIGIT_RNG_17    \xE0\xBC[\xA0-\xA9]
DIGIT_RNG_18    \xE1\x81[\x80-\x89]
DIGIT_RNG_19    \xE1\x82[\x90-\x99]
DIGIT_RNG_20    \xE1\x9F[\xA0-\xA9]
DIGIT_RNG_21    \xE1\xA0[\x90-\x99]
DIGIT_RNG_22    \xE1\xA5[\x86-\x8F]
DIGIT_RNG_23    \xE1\xA7[\x90-\x99]
DIGIT_RNG_24    \xE1\xAA[\x80-\x99]
DIGIT_RNG_25    \xE1\xAD[\x90-\x99]
DIGIT_RNG_26    \xE1\xAE[\xB0-\xB9]
DIGIT_RNG_27    \xE1\xB1[\x80-\x89]
DIGIT_RNG_28    \xE1\xB1[\x90-\x99]
DIGIT_RNG_29    \xEA\x98[\xA0-\xA9]
DIGIT_RNG_30    \xEA\xA3[\x90-\x99]
DIGIT_RNG_31    \xEA\xA4[\x80-\x89]
DIGIT_RNG_32    \xEA\xA7[\x90-\x99]
DIGIT_RNG_33    \xEA\xA7[\xB0-\xB9]
DIGIT_RNG_34    \xEA\xA9[\x90-\x99]
DIGIT_RNG_35    \xEA\xAF[\xB0-\xB9]
DIGIT_RNG_36    \xEF\xBC[\x90-\x99]
DIGIT_RNG_37    \xF0\x90\x92[\xA0-\xA9]
DIGIT_RNG_38    \xF0\x90\xB4[\xB0-\xB9]
DIGIT_RNG_39    \xF0\x91\x81[\xA6-\xAF]
DIGIT_RNG_40    \xF0\x91\x83[\xB0-\xB9]
DIGIT_RNG_41    \xF0\x91\x84[\xB6-\xBF]
DIGIT_RNG_42    \xF0\x91\x87[\x90-\x99]
DIGIT_RNG_43    \xF0\x91\x8B[\xB0-\xB9]
DIGIT_RNG_44    \xF0\x91\x91[\x90-\x99]
DIGIT_RNG_45    \xF0\x91\x93[\x90-\x99]
DIGIT_RNG_46    \xF0\x91\x99[\x90-\x99]
DIGIT_RNG_47    \xF0\x91\x9B[\x80-\x89]
DIGIT_RNG_48    \xF0\x91\x9C[\xB0-\xB9]
DIGIT_RNG_49    \xF0\x91\xA3[\xA0-\xA9]
DIGIT_RNG_50    \xF0\x91\xA5[\x90-\x99]
DIGIT_RNG_51    \xF0\x91\xB1[\x90-\x99]
DIGIT_RNG_52    \xF0\x91\xB5[\x90-\x99]
DIGIT_RNG_53    \xF0\x91\xB6[\xA0-\xA9]
DIGIT_RNG_54    \xF0\x96\xA9[\xA0-\xA9]
DIGIT_RNG_55    \xF0\x96\xAD[\x90-\x99]
DIGIT_RNG_56    \xF0\x9D\x9F[\x8E-\xBF]
DIGIT_RNG_57    \xF0\x9E\x85[\x80-\x89]
DIGIT_RNG_58    \xF0\x9E\x8B[\xB0-\xB9]
DIGIT_RNG_59    \xF0\x9E\xA5[\x90-\x99]
DIGIT_RNG_60    \xF0\x9F\xAF[\xB0-\xB9]

DIGIT_GROUP_1    {DIGIT_RNG_1}|{DIGIT_RNG_2}|{DIGIT_RNG_3}|{DIGIT_RNG_4}|{DIGIT_RNG_5}|{DIGIT_RNG_6}|{DIGIT_RNG_7}|{DIGIT_RNG_8}|{DIGIT_RNG_10}
DIGIT_GROUP_2    {DIGIT_GROUP_1}|{DIGIT_RNG_11}|{DIGIT_RNG_12}|{DIGIT_RNG_13}|{DIGIT_RNG_14}|{DIGIT_RNG_15}|{DIGIT_RNG_16}|{DIGIT_RNG_17}|{DIGIT_RNG_18}
DIGIT_GROUP_3    {DIGIT_GROUP_2}|{DIGIT_RNG_19}|{DIGIT_RNG_20}|{DIGIT_RNG_21}|{DIGIT_RNG_22}|{DIGIT_RNG_23}|{DIGIT_RNG_24}|{DIGIT_RNG_25}|{DIGIT_RNG_26}
DIGIT_GROUP_4    {DIGIT_GROUP_3}|{DIGIT_RNG_27}|{DIGIT_RNG_28}|{DIGIT_RNG_29}|{DIGIT_RNG_30}|{DIGIT_RNG_31}|{DIGIT_RNG_32}|{DIGIT_RNG_33}|{DIGIT_RNG_34}
DIGIT_GROUP_5    {DIGIT_GROUP_4}|{DIGIT_RNG_35}|{DIGIT_RNG_36}|{DIGIT_RNG_37}|{DIGIT_RNG_38}|{DIGIT_RNG_39}|{DIGIT_RNG_40}|{DIGIT_RNG_41}|{DIGIT_RNG_42}
DIGIT_GROUP_6    {DIGIT_GROUP_5}|{DIGIT_RNG_43}|{DIGIT_RNG_44}|{DIGIT_RNG_45}|{DIGIT_RNG_46}|{DIGIT_RNG_47}|{DIGIT_RNG_48}|{DIGIT_RNG_49}|{DIGIT_RNG_50}
DIGIT_GROUP_7    {DIGIT_GROUP_6}|{DIGIT_RNG_51}|{DIGIT_RNG_52}|{DIGIT_RNG_53}|{DIGIT_RNG_54}|{DIGIT_RNG_55}|{DIGIT_RNG_56}|{DIGIT_RNG_57}|{DIGIT_RNG_58}
DIGIT_GROUP_8    {DIGIT_GROUP_7}|{DIGIT_RNG_59}|{DIGIT_RNG_60}

UNICODE_DIGIT    {DIGIT_GROUP_1}|{DIGIT_GROUP_2}|{DIGIT_GROUP_3}|{DIGIT_GROUP_4}|{DIGIT_GROUP_5}|{DIGIT_GROUP_6}|{DIGIT_GROUP_7}|{DIGIT_GROUP_8}

/* Unicode combining mark ranges (categories Mn and Mc) */
/* generated with unicode_range_generator.l */
/* UTF-8 ranges generated with https://lists.gnu.org/archive/html/help-flex/2005-01/msg00043.html */
COMB_MARK_RNG_1      \xCD[\x80-\xAF]|\xCC[\x80-\xBF]
COMB_MARK_RNG_2      \xD2[\x83-\x87]
COMB_MARK_RNG_3      \xD6[\x91-\xBD]
COMB_MARK_RNG_4      \xD6\xBF
COMB_MARK_RNG_5      \xD7[\x81-\x82]
COMB_MARK_RNG_6      \xD7[\x84-\x85]
COMB_MARK_RNG_7      \xD7\x87
COMB_MARK_RNG_8      \xD8[\x90-\x9A]
COMB_MARK_RNG_9      \xD9[\x8B-\x9F]
COMB_MARK_RNG_10     \xD9\xB0
COMB_MARK_RNG_11     \xDB[\x96-\x9C]
COMB_MARK_RNG_12     \xDB[\x9F-\xA4]
COMB_MARK_RNG_13     \xDB[\xA7-\xA8]
COMB_MARK_RNG_14     \xDB[\xAA-\xAD]
COMB_MARK_RNG_15     \xDC\x91
COMB_MARK_RNG_16     \xDC[\xB0-\xBF]|\xDD[\x80-\x8A]
COMB_MARK_RNG_17     \xDE[\xA6-\xB0]
COMB_MARK_RNG_18     \xDF[\xAB-\xB3]
COMB_MARK_RNG_19     \xDF\xBD
COMB_MARK_RNG_20     \xE0\xA0[\x96-\x99]
COMB_MARK_RNG_21     \xE0\xA0[\x9B-\xA3]
COMB_MARK_RNG_22     \xE0\xA0[\xA5-\xA7]
COMB_MARK_RNG_23     \xE0\xA0[\xA9-\xAD]
COMB_MARK_RNG_24     \xE0\xA1[\x99-\x9B]
COMB_MARK_RNG_25     \xE0\xA3[\x93-\xA1]
COMB_MARK_RNG_26     \xE0(\xA3[\xA3-\xBF]|\xA4[\x80-\x83])
COMB_MARK_RNG_27     \xE0\xA4[\xBA-\xBC]
COMB_MARK_RNG_28     \xE0(\xA4[\xBE-\xBF]|\xA5[\x80-\x8F])
COMB_MARK_RNG_29     \xE0\xA5[\x91-\x97]
COMB_MARK_RNG_30     \xE0\xA5[\xA2-\xA3]
COMB_MARK_RNG_31     \xE0\xA6[\x81-\x83]
COMB_MARK_RNG_32     \xE0\xA6\xBC
COMB_MARK_RNG_33     \xE0(\xA6[\xBE-\xBF]|\xA7[\x80-\x8D])
COMB_MARK_RNG_34     \xE0\xA7\x97
COMB_MARK_RNG_35     \xE0\xA7[\xA2-\xA3]
COMB_MARK_RNG_36     \xE0(\xA7[\xBE-\xBF]|\xA8[\x80-\x83])
COMB_MARK_RNG_37     \xE0(\xA8[\xBC-\xBF]|\xA9[\x80-\x91])
COMB_MARK_RNG_38     \xE0\xA9[\xB0-\xB1]
COMB_MARK_RNG_39     \xE0\xA9\xB5
COMB_MARK_RNG_40     \xE0\xAA[\x81-\x83]
COMB_MARK_RNG_41     \xE0\xAA\xBC
COMB_MARK_RNG_42     \xE0(\xAA[\xBE-\xBF]|\xAB[\x80-\x8D])
COMB_MARK_RNG_43     \xE0\xAB[\xA2-\xA3]
COMB_MARK_RNG_44     \xE0(\xAB[\xBA-\xBF]|\xAC[\x80-\x83])
COMB_MARK_RNG_45     \xE0\xAC\xBC
COMB_MARK_RNG_46     \xE0(\xAC[\xBE-\xBF]|\xAD[\x80-\x97])
COMB_MARK_RNG_47     \xE0\xAD[\xA2-\xA3]
COMB_MARK_RNG_48     \xE0\xAE\x82
COMB_MARK_RNG_49     \xE0(\xAE[\xBE-\xBF]|\xAF[\x80-\x8D])
COMB_MARK_RNG_50     \xE0\xAF\x97
COMB_MARK_RNG_51     \xE0\xB0[\x80-\x84]
COMB_MARK_RNG_52     \xE0(\xB0[\xBE-\xBF]|\xB1[\x80-\x96])
COMB_MARK_RNG_53     \xE0\xB1[\xA2-\xA3]
COMB_MARK_RNG_54     \xE0\xB2[\x81-\x83]
COMB_MARK_RNG_55     \xE0\xB2\xBC
COMB_MARK_RNG_56     \xE0(\xB2[\xBE-\xBF]|\xB3[\x80-\x96])
COMB_MARK_RNG_57     \xE0\xB3[\xA2-\xA3]
COMB_MARK_RNG_58     \xE0\xB4[\x80-\x83]
COMB_MARK_RNG_59     \xE0\xB4[\xBB-\xBC]
COMB_MARK_RNG_60     \xE0(\xB4[\xBE-\xBF]|\xB5[\x80-\x8D])
COMB_MARK_RNG_61     \xE0\xB5\x97
COMB_MARK_RNG_62     \xE0\xB5[\xA2-\xA3]
COMB_MARK_RNG_63     \xE0\xB6[\x81-\x83]
COMB_MARK_RNG_64     \xE0\xB7[\x8A-\x9F]
COMB_MARK_RNG_65     \xE0\xB7[\xB2-\xB3]
COMB_MARK_RNG_66     \xE0\xB8\xB1
COMB_MARK_RNG_67     \xE0\xB8[\xB4-\xBA]
COMB_MARK_RNG_68     \xE0\xB9[\x87-\x8E]
COMB_MARK_RNG_69     \xE0\xBA\xB1
COMB_MARK_RNG_70     \xE0\xBA[\xB4-\xBC]
COMB_MARK_RNG_71     \xE0\xBB[\x88-\x8D]
COMB_MARK_RNG_72     \xE0\xBC[\x98-\x99]
COMB_MARK_RNG_73     \xE0\xBC\xB5
COMB_MARK_RNG_74     \xE0\xBC\xB7
COMB_MARK_RNG_75     \xE0\xBC\xB9
COMB_MARK_RNG_76     \xE0\xBC[\xBE-\xBF]
COMB_MARK_RNG_77     \xE0(\xBD[\xB1-\xBF]|\xBE[\x80-\x84])
COMB_MARK_RNG_78     \xE0\xBE[\x86-\x87]
COMB_MARK_RNG_79     \xE0\xBE[\x8D-\xBC]
COMB_MARK_RNG_80     \xE0\xBF\x86
COMB_MARK_RNG_81     \xE1\x80[\xAB-\xBE]
COMB_MARK_RNG_82     \xE1\x81[\x96-\x99]
COMB_MARK_RNG_83     \xE1\x81[\x9E-\xA0]
COMB_MARK_RNG_84     \xE1\x81[\xA2-\xA4]
COMB_MARK_RNG_85     \xE1\x81[\xA7-\xAD]
COMB_MARK_RNG_86     \xE1\x81[\xB1-\xB4]
COMB_MARK_RNG_87     \xE1\x82[\x82-\x8D]
COMB_MARK_RNG_88     \xE1\x82\x8F
COMB_MARK_RNG_89     \xE1\x82[\x9A-\x9D]
COMB_MARK_RNG_90     \8xE1\x8D[\x9D-\x9F]
COMB_MARK_RNG_91     \xE1\x9C[\x92-\x94]
COMB_MARK_RNG_92     \xE1\x9C[\xB2-\xB4]
COMB_MARK_RNG_93     \xE1\x9D[\x92-\x93]
COMB_MARK_RNG_94     \xE1\x9D[\xB2-\xB3]
COMB_MARK_RNG_95     \xE1(\x9E[\xB4-\xBF]|\x9F[\x80-\x93])
COMB_MARK_RNG_96     \xE1\x9F\x9D
COMB_MARK_RNG_97     \xE1\xA0[\x8B-\x8D]
COMB_MARK_RNG_98     \xE1\xA2[\x85-\x86]
COMB_MARK_RNG_99     \xE1\xA2\xA9
COMB_MARK_RNG_100    \xE1\xA4[\xA0-\xBB]
COMB_MARK_RNG_101    \xE1\xA8[\x97-\x9B]
COMB_MARK_RNG_102    \xE1\xA9[\x95-\xBF]
COMB_MARK_RNG_103    \xE1\xAA[\xB0-\xBD]
COMB_MARK_RNG_104    \xE1(\xAA\xBF|\xAC[\x80-\x84]|\xAB[\x80-\xBF])
COMB_MARK_RNG_105    \xE1(\xAC[\xB4-\xBF]|\xAD[\x80-\x84])
COMB_MARK_RNG_106    \xE1\xAD[\xAB-\xB3]
COMB_MARK_RNG_107    \xE1\xAE[\x80-\x82]
COMB_MARK_RNG_108    \xE1\xAE[\xA1-\xAD]
COMB_MARK_RNG_109    \xE1\xAF[\xA6-\xB3]
COMB_MARK_RNG_110    \xE1\xB0[\xA4-\xB7]
COMB_MARK_RNG_111    \xE1\xB3[\x90-\x92]
COMB_MARK_RNG_112    \xE1\xB3[\x94-\xA8]
COMB_MARK_RNG_113    \xE1\xB3\xAD
COMB_MARK_RNG_114    \xE1\xB3\xB4
COMB_MARK_RNG_115    \xE1\xB3[\xB7-\xB9]
COMB_MARK_RNG_116    \xE1\xB7[\x80-\xBF]
COMB_MARK_RNG_117    \xE2\x83[\x90-\x9C]
COMB_MARK_RNG_118    \xE2\x83\xA1
COMB_MARK_RNG_119    \xE2\x83[\xA5-\xB0]
COMB_MARK_RNG_120    \xE2\xB3[\xAF-\xB1]
COMB_MARK_RNG_121    \xE2\xB5\xBF
COMB_MARK_RNG_122    \xE2\xB7[\xA0-\xBF]
COMB_MARK_RNG_123    \xE3\x80[\xAA-\xAF]
COMB_MARK_RNG_124    \xE3\x82[\x99-\x9A]
COMB_MARK_RNG_125    \xEA\x99\xAF
COMB_MARK_RNG_126    \xEA\x99[\xB4-\xBD]
COMB_MARK_RNG_127    \xEA\x9A[\x9E-\x9F]
COMB_MARK_RNG_128    \xEA\x9B[\xB0-\xB1]
COMB_MARK_RNG_129    \xEA\xA0\x82
COMB_MARK_RNG_130    \xEA\xA0\x86
COMB_MARK_RNG_131    \xEA\xA0\x8B
COMB_MARK_RNG_132    \xEA\xA0[\xA3-\xA7]
COMB_MARK_RNG_133    \xEA\xA0\xAC
COMB_MARK_RNG_134    \xEA\xA2[\x80-\x81]
COMB_MARK_RNG_135    \xEA(\xA2[\xB4-\xBF]|\xA3[\x80-\x85])
COMB_MARK_RNG_136    \xEA\xA3[\xA0-\xB1]
COMB_MARK_RNG_137    \xEA\xA3\xBF
COMB_MARK_RNG_138    \xEA\xA4[\xA6-\xAD]
COMB_MARK_RNG_139    \xEA\xA5[\x87-\x93]
COMB_MARK_RNG_140    \xEA\xA6[\x80-\x83]
COMB_MARK_RNG_141    \xEA(\xA6[\xB3-\xBF]|\xA7\x80)
COMB_MARK_RNG_142    \xEA\xA7\xA5
COMB_MARK_RNG_143    \xEA\xA8[\xA9-\xB6]
COMB_MARK_RNG_144    \xEA\xA9\x83
COMB_MARK_RNG_145    \xEA\xA9[\x8C-\x8D]
COMB_MARK_RNG_146    \xEA\xA9[\xBB-\xBD]
COMB_MARK_RNG_147    \xEA\xAA\xB0
COMB_MARK_RNG_148    \xEA\xAA[\xB2-\xB4]
COMB_MARK_RNG_149    \xEA\xAA[\xB7-\xB8]
COMB_MARK_RNG_150    \xEA\xAA[\xBE-\xBF]
COMB_MARK_RNG_151    \xEA\xAB\x81
COMB_MARK_RNG_152    \xEA\xAB[\xAB-\xAF]
COMB_MARK_RNG_153    \xEA\xAB[\xB5-\xB6]
COMB_MARK_RNG_154    \xEA\xAF[\xA3-\xAA]
COMB_MARK_RNG_155    \xEA\xAF[\xAC-\xAD]
COMB_MARK_RNG_156    \xEF\xAC\x9E
COMB_MARK_RNG_157    \xEF\xB8[\x80-\x8F]
COMB_MARK_RNG_158    \xEF\xB8[\xA0-\xAF]
COMB_MARK_RNG_159    \xF0\x90\x87\xBD
COMB_MARK_RNG_160    \xF0\x90\x8B\xA0
COMB_MARK_RNG_161    \xF0\x90\x8D[\xB6-\xBA]
COMB_MARK_RNG_162    \xF0\x90\xA8[\x81-\x8F]
COMB_MARK_RNG_163    \xF0\x90\xA8[\xB8-\xBF]
COMB_MARK_RNG_164    \xF0\x90\xAB[\xA5-\xA6]
COMB_MARK_RNG_165    \xF0\x90\xB4[\xA4-\xA7]
COMB_MARK_RNG_166    \xF0\x90\xBA[\xAB-\xAC]
COMB_MARK_RNG_167    \xF0\x90\xBD[\x86-\x90]
COMB_MARK_RNG_168    \xF0\x91\x80[\x80-\x82]
COMB_MARK_RNG_169    \xF0\x91(\x80[\xB8-\xBF]|\x81[\x80-\x86])
COMB_MARK_RNG_170    \xF0\x91(\x81\xBF|\x82[\x80-\x82])
COMB_MARK_RNG_171    \xF0\x91\x82[\xB0-\xBA]
COMB_MARK_RNG_172    \xF0\x91\x84[\x80-\x82]
COMB_MARK_RNG_173    \xF0\x91\x84[\xA7-\xB4]
COMB_MARK_RNG_174    \xF0\x91\x85[\x85-\x86]
COMB_MARK_RNG_175    \xF0\x91\x85\xB3
COMB_MARK_RNG_176    \xF0\x91\x86[\x80-\x82]
COMB_MARK_RNG_177    \xF0\x91(\x86[\xB3-\xBF]|\x87\x80)
COMB_MARK_RNG_178    \xF0\x91\x87[\x89-\x8C]
COMB_MARK_RNG_179    \xF0\x91\x87[\x8E-\x8F]
COMB_MARK_RNG_180    \xF0\x91\x88[\xAC-\xB7]
COMB_MARK_RNG_181    \xF0\x91\x88\xBE
COMB_MARK_RNG_182    \xF0\x91\x8B[\x9F-\xAA]
COMB_MARK_RNG_183    \xF0\x91\x8C[\x80-\x83]
COMB_MARK_RNG_184    \xF0\x91\x8C[\xBB-\xBC]
COMB_MARK_RNG_185    \xF0\x91(\x8C[\xBE-\xBF]|\x8D[\x80-\x8D])
COMB_MARK_RNG_186    \xF0\x91\x8D\x97
COMB_MARK_RNG_187    \xF0\x91\x8D[\xA2-\xB4]
COMB_MARK_RNG_188    \xF0\x91(\x90[\xB5-\xBF]|\x91[\x80-\x86])
COMB_MARK_RNG_189    \xF0\x91\x91\x9E
COMB_MARK_RNG_190    \xF0\x91(\x92[\xB0-\xBF]|\x93[\x80-\x83])
COMB_MARK_RNG_191    \xF0\x91(\x96[\xAF-\xBF]|\x97\x80)
COMB_MARK_RNG_192    \xF0\x91\x97[\x9C-\x9D]
COMB_MARK_RNG_193    \xF0\x91(\x98[\xB0-\xBF]|\x99\x80)
COMB_MARK_RNG_194    \xF0\x91\x9A[\xAB-\xB7]
COMB_MARK_RNG_195    \xF0\x91\x9C[\x9D-\xAB]
COMB_MARK_RNG_196    \xF0\x91\xA0[\xAC-\xBA]
COMB_MARK_RNG_197    \xF0\x91\xA4[\xB0-\xBE]
COMB_MARK_RNG_198    \xF0\x91\xA5\x80
COMB_MARK_RNG_199    \xF0\x91\xA5[\x82-\x83]
COMB_MARK_RNG_200    \xF0\x91\xA7[\x91-\xA0]
COMB_MARK_RNG_201    \xF0\x91\xA7\xA4
COMB_MARK_RNG_202    \xF0\x91\xA8[\x81-\x8A]
COMB_MARK_RNG_203    \xF0\x91\xA8[\xB3-\xB9]
COMB_MARK_RNG_204    \xF0\x91\xA8[\xBB-\xBE]
COMB_MARK_RNG_205    \xF0\x91\xA9\x87
COMB_MARK_RNG_206    \xF0\x91\xA9[\x91-\x9B]
COMB_MARK_RNG_207    \xF0\x91\xAA[\x8A-\x99]
COMB_MARK_RNG_208    \xF0\x91\xB0[\xAF-\xBF]
COMB_MARK_RNG_209    \xF0\x91\xB2[\x92-\xB6]
COMB_MARK_RNG_210    \xF0\x91(\xB4[\xB1-\xBF]|\xB5[\x80-\x85])
COMB_MARK_RNG_211    \xF0\x91\xB5\x87
COMB_MARK_RNG_212    \xF0\x91\xB6[\x8A-\x97]
COMB_MARK_RNG_213    \xF0\x91\xBB[\xB3-\xB6]
COMB_MARK_RNG_214    \xF0\x96\xAB[\xB0-\xB4]
COMB_MARK_RNG_215    \xF0\x96\xAC[\xB0-\xB6]
COMB_MARK_RNG_216    \xF0\x96\xBD\x8F
COMB_MARK_RNG_217    \xF0\x96(\xBD[\x91-\xBF]|\xBE[\x80-\x92])
COMB_MARK_RNG_218    \xF0\x96\xBF[\xA4-\xB1]
COMB_MARK_RNG_219    \xF0\x9B\xB2[\x9D-\x9E]
COMB_MARK_RNG_220    \xF0\x9D\x85[\xA5-\xA9]
COMB_MARK_RNG_221    \xF0\x9D\x85[\xAD-\xB2]
COMB_MARK_RNG_222    \xF0\x9D(\x85[\xBB-\xBF]|\x86[\x80-\x82])
COMB_MARK_RNG_223    \xF0\x9D\x86[\x85-\x8B]
COMB_MARK_RNG_224    \xF0\x9D\x86[\xAA-\xAD]
COMB_MARK_RNG_225    \xF0\x9D\x89[\x82-\x84]
COMB_MARK_RNG_226    \xF0\x9D\xA8[\x80-\xB6]
COMB_MARK_RNG_227    \xF0\x9D(\xA8[\xBB-\xBF]|\xA9[\x80-\xAC])
COMB_MARK_RNG_228    \xF0\x9D\xA9\xB5
COMB_MARK_RNG_229    \xF0\x9D\xAA\x84
COMB_MARK_RNG_230    \xF0(\x9D\xAA[\x9B-\xBF]|\x9E\x80[\x80-\xAA]|\x9D[\xAB-\xBF][\x80-\xBF])
COMB_MARK_RNG_231    \xF0\x9E\x84[\xB0-\xB6]
COMB_MARK_RNG_232    \xF0\x9E\x8B[\xAC-\xAF]
COMB_MARK_RNG_233    \xF0\x9E\xA3[\x90-\x96]
COMB_MARK_RNG_234    \xF0\x9E\xA5[\x84-\x8A]
COMB_MARK_RNG_235    \xF3\xA0(\x87[\x80-\xAF]|[\x84-\x86][\x80-\xBF])

COMB_MARK_GROUP_1     {COMB_MARK_RNG_1}|{COMB_MARK_RNG_2}|{COMB_MARK_RNG_3}|{COMB_MARK_RNG_4}|{COMB_MARK_RNG_5}|{COMB_MARK_RNG_6}|{COMB_MARK_RNG_7}|{COMB_MARK_RNG_8}|{COMB_MARK_RNG_9}|{COMB_MARK_RNG_10}
COMB_MARK_GROUP_2     {COMB_MARK_GROUP_1}|{COMB_MARK_RNG_11}|{COMB_MARK_RNG_12}|{COMB_MARK_RNG_13}|{COMB_MARK_RNG_14}|{COMB_MARK_RNG_15}|{COMB_MARK_RNG_16}|{COMB_MARK_RNG_17}|{COMB_MARK_RNG_18}|{COMB_MARK_RNG_19}
COMB_MARK_GROUP_3     {COMB_MARK_GROUP_2}|{COMB_MARK_RNG_20}|{COMB_MARK_RNG_21}|{COMB_MARK_RNG_22}|{COMB_MARK_RNG_23}|{COMB_MARK_RNG_24}|{COMB_MARK_RNG_25}|{COMB_MARK_RNG_26}|{COMB_MARK_RNG_27}|{COMB_MARK_RNG_28}
COMB_MARK_GROUP_4     {COMB_MARK_GROUP_3}|{COMB_MARK_RNG_29}|{COMB_MARK_RNG_30}|{COMB_MARK_RNG_31}|{COMB_MARK_RNG_32}|{COMB_MARK_RNG_33}|{COMB_MARK_RNG_34}|{COMB_MARK_RNG_35}|{COMB_MARK_RNG_36}|{COMB_MARK_RNG_37}
COMB_MARK_GROUP_5     {COMB_MARK_GROUP_4}|{COMB_MARK_RNG_38}|{COMB_MARK_RNG_39}|{COMB_MARK_RNG_40}|{COMB_MARK_RNG_41}|{COMB_MARK_RNG_42}|{COMB_MARK_RNG_43}|{COMB_MARK_RNG_44}|{COMB_MARK_RNG_45}|{COMB_MARK_RNG_46}
COMB_MARK_GROUP_6     {COMB_MARK_GROUP_5}|{COMB_MARK_RNG_47}|{COMB_MARK_RNG_48}|{COMB_MARK_RNG_49}|{COMB_MARK_RNG_50}|{COMB_MARK_RNG_51}|{COMB_MARK_RNG_52}|{COMB_MARK_RNG_53}|{COMB_MARK_RNG_54}|{COMB_MARK_RNG_55}
COMB_MARK_GROUP_7     {COMB_MARK_GROUP_6}|{COMB_MARK_RNG_56}|{COMB_MARK_RNG_57}|{COMB_MARK_RNG_58}|{COMB_MARK_RNG_59}|{COMB_MARK_RNG_60}|{COMB_MARK_RNG_61}|{COMB_MARK_RNG_62}|{COMB_MARK_RNG_63}|{COMB_MARK_RNG_64}
COMB_MARK_GROUP_8     {COMB_MARK_GROUP_7}|{COMB_MARK_RNG_65}|{COMB_MARK_RNG_66}|{COMB_MARK_RNG_67}|{COMB_MARK_RNG_68}|{COMB_MARK_RNG_69}|{COMB_MARK_RNG_70}|{COMB_MARK_RNG_71}|{COMB_MARK_RNG_72}|{COMB_MARK_RNG_73}
COMB_MARK_GROUP_9     {COMB_MARK_GROUP_8}|{COMB_MARK_RNG_74}|{COMB_MARK_RNG_75}|{COMB_MARK_RNG_76}|{COMB_MARK_RNG_77}|{COMB_MARK_RNG_78}|{COMB_MARK_RNG_79}|{COMB_MARK_RNG_80}|{COMB_MARK_RNG_81}|{COMB_MARK_RNG_82}
COMB_MARK_GROUP_10    {COMB_MARK_GROUP_9}|{COMB_MARK_RNG_83}|{COMB_MARK_RNG_84}|{COMB_MARK_RNG_85}|{COMB_MARK_RNG_86}|{COMB_MARK_RNG_87}|{COMB_MARK_RNG_88}|{COMB_MARK_RNG_89}|{COMB_MARK_RNG_90}|{COMB_MARK_RNG_91}
COMB_MARK_GROUP_11    {COMB_MARK_GROUP_10}|{COMB_MARK_RNG_92}|{COMB_MARK_RNG_93}|{COMB_MARK_RNG_94}|{COMB_MARK_RNG_95}|{COMB_MARK_RNG_96}|{COMB_MARK_RNG_97}|{COMB_MARK_RNG_98}|{COMB_MARK_RNG_99}|{COMB_MARK_RNG_100}
COMB_MARK_GROUP_12    {COMB_MARK_GROUP_11}|{COMB_MARK_RNG_101}|{COMB_MARK_RNG_102}|{COMB_MARK_RNG_103}|{COMB_MARK_RNG_104}|{COMB_MARK_RNG_105}|{COMB_MARK_RNG_106}|{COMB_MARK_RNG_107}|{COMB_MARK_RNG_108}|{COMB_MARK_RNG_109}
COMB_MARK_GROUP_13    {COMB_MARK_GROUP_12}|{COMB_MARK_RNG_110}|{COMB_MARK_RNG_111}|{COMB_MARK_RNG_112}|{COMB_MARK_RNG_113}|{COMB_MARK_RNG_114}|{COMB_MARK_RNG_115}|{COMB_MARK_RNG_116}|{COMB_MARK_RNG_117}|{COMB_MARK_RNG_118}
COMB_MARK_GROUP_14    {COMB_MARK_GROUP_13}|{COMB_MARK_RNG_119}|{COMB_MARK_RNG_120}|{COMB_MARK_RNG_121}|{COMB_MARK_RNG_122}|{COMB_MARK_RNG_123}|{COMB_MARK_RNG_124}|{COMB_MARK_RNG_125}|{COMB_MARK_RNG_126}|{COMB_MARK_RNG_127}
COMB_MARK_GROUP_15    {COMB_MARK_GROUP_14}|{COMB_MARK_RNG_128}|{COMB_MARK_RNG_129}|{COMB_MARK_RNG_130}|{COMB_MARK_RNG_131}|{COMB_MARK_RNG_132}|{COMB_MARK_RNG_133}|{COMB_MARK_RNG_134}|{COMB_MARK_RNG_135}|{COMB_MARK_RNG_136}
COMB_MARK_GROUP_16    {COMB_MARK_GROUP_15}|{COMB_MARK_RNG_137}|{COMB_MARK_RNG_138}|{COMB_MARK_RNG_139}|{COMB_MARK_RNG_140}|{COMB_MARK_RNG_141}|{COMB_MARK_RNG_142}|{COMB_MARK_RNG_143}|{COMB_MARK_RNG_144}|{COMB_MARK_RNG_145}
COMB_MARK_GROUP_17    {COMB_MARK_GROUP_16}|{COMB_MARK_RNG_146}|{COMB_MARK_RNG_147}|{COMB_MARK_RNG_148}|{COMB_MARK_RNG_149}|{COMB_MARK_RNG_150}|{COMB_MARK_RNG_151}|{COMB_MARK_RNG_152}|{COMB_MARK_RNG_153}|{COMB_MARK_RNG_154}
COMB_MARK_GROUP_18    {COMB_MARK_GROUP_17}|{COMB_MARK_RNG_155}|{COMB_MARK_RNG_156}|{COMB_MARK_RNG_157}|{COMB_MARK_RNG_158}|{COMB_MARK_RNG_159}|{COMB_MARK_RNG_160}|{COMB_MARK_RNG_161}|{COMB_MARK_RNG_162}|{COMB_MARK_RNG_163}
COMB_MARK_GROUP_19    {COMB_MARK_GROUP_18}|{COMB_MARK_RNG_164}|{COMB_MARK_RNG_165}|{COMB_MARK_RNG_166}|{COMB_MARK_RNG_167}|{COMB_MARK_RNG_168}|{COMB_MARK_RNG_169}|{COMB_MARK_RNG_170}|{COMB_MARK_RNG_171}|{COMB_MARK_RNG_172}
COMB_MARK_GROUP_20    {COMB_MARK_GROUP_19}|{COMB_MARK_RNG_173}|{COMB_MARK_RNG_174}|{COMB_MARK_RNG_175}|{COMB_MARK_RNG_176}|{COMB_MARK_RNG_177}|{COMB_MARK_RNG_178}|{COMB_MARK_RNG_179}|{COMB_MARK_RNG_180}|{COMB_MARK_RNG_181}
COMB_MARK_GROUP_21    {COMB_MARK_GROUP_20}|{COMB_MARK_RNG_182}|{COMB_MARK_RNG_183}|{COMB_MARK_RNG_184}|{COMB_MARK_RNG_185}|{COMB_MARK_RNG_186}|{COMB_MARK_RNG_187}|{COMB_MARK_RNG_188}|{COMB_MARK_RNG_189}|{COMB_MARK_RNG_190}
COMB_MARK_GROUP_22    {COMB_MARK_GROUP_21}|{COMB_MARK_RNG_191}|{COMB_MARK_RNG_192}|{COMB_MARK_RNG_193}|{COMB_MARK_RNG_194}|{COMB_MARK_RNG_195}|{COMB_MARK_RNG_196}|{COMB_MARK_RNG_197}|{COMB_MARK_RNG_198}|{COMB_MARK_RNG_199}
COMB_MARK_GROUP_23    {COMB_MARK_GROUP_22}|{COMB_MARK_RNG_200}|{COMB_MARK_RNG_201}|{COMB_MARK_RNG_202}|{COMB_MARK_RNG_203}|{COMB_MARK_RNG_204}|{COMB_MARK_RNG_205}|{COMB_MARK_RNG_206}|{COMB_MARK_RNG_207}|{COMB_MARK_RNG_208}
COMB_MARK_GROUP_24    {COMB_MARK_GROUP_23}|{COMB_MARK_RNG_209}|{COMB_MARK_RNG_210}|{COMB_MARK_RNG_211}|{COMB_MARK_RNG_212}|{COMB_MARK_RNG_213}|{COMB_MARK_RNG_214}|{COMB_MARK_RNG_215}|{COMB_MARK_RNG_216}|{COMB_MARK_RNG_217}
COMB_MARK_GROUP_25    {COMB_MARK_GROUP_24}|{COMB_MARK_RNG_218}|{COMB_MARK_RNG_219}|{COMB_MARK_RNG_220}|{COMB_MARK_RNG_221}|{COMB_MARK_RNG_222}|{COMB_MARK_RNG_223}|{COMB_MARK_RNG_224}|{COMB_MARK_RNG_225}|{COMB_MARK_RNG_226}
COMB_MARK_GROUP_26    {COMB_MARK_GROUP_25}|{COMB_MARK_RNG_227}|{COMB_MARK_RNG_228}|{COMB_MARK_RNG_229}|{COMB_MARK_RNG_230}|{COMB_MARK_RNG_231}|{COMB_MARK_RNG_232}|{COMB_MARK_RNG_233}|{COMB_MARK_RNG_234}|{COMB_MARK_RNG_235}

COMB_MARK_G_GROUP_1    {COMB_MARK_GROUP_1}|{COMB_MARK_GROUP_2}|{COMB_MARK_GROUP_3}|{COMB_MARK_GROUP_4}|{COMB_MARK_GROUP_5}|{COMB_MARK_GROUP_6}|{COMB_MARK_GROUP_7}|{COMB_MARK_GROUP_8}|{COMB_MARK_GROUP_9}|{COMB_MARK_GROUP_10}
COMB_MARK_G_GROUP_2    {COMB_MARK_G_GROUP_1}|{COMB_MARK_GROUP_11}|{COMB_MARK_GROUP_12}|{COMB_MARK_GROUP_13}|{COMB_MARK_GROUP_14}|{COMB_MARK_GROUP_15}|{COMB_MARK_GROUP_16}|{COMB_MARK_GROUP_17}|{COMB_MARK_GROUP_18}|{COMB_MARK_GROUP_19}
COMB_MARK_G_GROUP_3    {COMB_MARK_G_GROUP_2}|{COMB_MARK_GROUP_20}|{COMB_MARK_GROUP_21}|{COMB_MARK_GROUP_22}|{COMB_MARK_GROUP_23}|{COMB_MARK_GROUP_24}|{COMB_MARK_GROUP_25}|{COMB_MARK_GROUP_26}

UNICODE_COMBINING_MARK    {COMB_MARK_G_GROUP_1}|{COMB_MARK_G_GROUP_2}|{COMB_MARK_G_GROUP_3}

/* Unicode connector punctuation ranges (category Pc) */
/* generated with unicode_range_generator.l */
/* UTF-8 ranges generated with https://lists.gnu.org/archive/html/help-flex/2005-01/msg00043.html */
CONNECTOR_PUNCT_RNG_1    _
CONNECTOR_PUNCT_RNG_2    \xE2(\x80\xBF|\x81\x80)
CONNECTOR_PUNCT_RNG_3    \xE2\x81\x94
CONNECTOR_PUNCT_RNG_4    \xEF\xB8[\xB3-\xB4]
CONNECTOR_PUNCT_RNG_5    \xEF\xB9[\x8D-\x8F]
CONNECTOR_PUNCT_RNG_6    \xEF\xBC\xBF

UNICODE_CONNECTOR_PUNCTUATION    {CONNECTOR_PUNCT_RNG_1}|{CONNECTOR_PUNCT_RNG_2}|{CONNECTOR_PUNCT_RNG_3}|{CONNECTOR_PUNCT_RNG_4}|{CONNECTOR_PUNCT_RNG_5}|{CONNECTOR_PUNCT_RNG_6}

UNICODE_ZWNJ    \xE2\x80\x8C
UNICODE_ZWJ     \xE2\x80\x8D

/* Unicode escape sequence */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.8.4 (escape sequence) */
UNICODE_ESCAPE_SEQUENCE    \\u[0-9a-fA-F]{4}

/* identifiers */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.6 */
IDENTIFIER_START    [_$]|({UNICODE_LETTER})|{UNICODE_ESCAPE_SEQUENCE}
IDENTIFIER_PART     (({IDENTIFIER_START})|({UNICODE_COMBINING_MARK})|({UNICODE_DIGIT})|({UNICODE_CONNECTOR_PUNCTUATION})|{UNICODE_ZWNJ}|{UNICODE_ZWJ})*
IDENTIFIER          ({IDENTIFIER_START}{IDENTIFIER_PART})*

/* literals */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-7.8 */
LITERAL_NULL                  null
LITERAL_BOOLEAN               true|false
LITERAL_DECIMAL               [.]?[0-9]+[\.]?[0-9]*[eE]?[0-9]*
LITERAL_HEX_INTEGER           0x[0-9a-fA-F]*|0X[0-9a-fA-F]*
LITERAL_DQ_STRING_START       \"
LITERAL_DQ_STRING_END         \"
LITERAL_DQ_STRING_SKIP        \\\"
LITERAL_DQ_STRING_TEXT        .
LITERAL_SQ_STRING_START       \'
LITERAL_SQ_STRING_END         \'
LITERAL_SQ_STRING_SKIP        \\\'
LITERAL_SQ_STRING_TEXT        .
LITERAL_TEMPLATE_START        \`
LITERAL_TEMPLATE_END          \`
LITERAL_TEMPLATE_SUBST_START  \$\{
LITERAL_TEMPLATE_OTHER        .
LITERAL_REGEX_START           \/[^*\/]
LITERAL_REGEX_END             \/[gimsuy]*
LITERAL_REGEX_SKIP            \\\/
/* extra literals */
/* according to https://ecma-international.org/ecma-262/5.1/#sec-4.3 */
LITERAL_UNDEFINED             undefined
LITERAL_INFINITY              Infinity|\xE2\x88\x9E
LITERAL_NAN                   NaN
LITERAL                       {LITERAL_NULL}|{LITERAL_BOOLEAN}|{LITERAL_DECIMAL}|{LITERAL_HEX_INTEGER}|{LITERAL_UNDEFINED}|{LITERAL_INFINITY}|{LITERAL_NAN}

HTML_COMMENT_OPEN         "<"+"!--"
HTML_TAG_SCRIPT_OPEN      "<"+(?i:script)
HTML_TAG_SCRIPT_CLOSE     "<"+(?i:\/script>)

/* from 0x000 to 0x10FFFD to match undefined tokens */
/* UTF-8 ranges generated with https://lists.gnu.org/archive/html/help-flex/2005-01/msg00043.html */
ALL_UNICODE    [\0-\x7F]|[\xC2-\xDF][\x80-\xBF]|(\xE0[\xA0-\xBF]|[\xE1-\xEF][\x80-\xBF])[\x80-\xBF]|\xF4\x8F\xBF[\x80-\xBD]|(\xF4\x8F[\x80-\xBE]|(\xF0[\x90-\xBF]|\xF4[\x80-\x8E]|[\xF1-\xF3][\x80-\xBF])[\x80-\xBF])[\x80-\xBF]

/* match regex literal only if the previous token was of type PUNCTUATOR_3 or KEYWORD */
/* this resolves an ambiguity with a division operator: var x = 2/2/1; */
%s regst

/* do not match division operators as punctuators if the previous token was of type PUNCTUATOR */
/* this resolves an ambiguity with regular expression in some cases such as (/=abc=/g) */
%s divop

/* in a single line comment */
%x lcomm

/* in a multi line comment */
%x bcomm

/* in a single-quoted string */
%x sqstr

/* in a double-quoted string */
%x dqstr

/* in a literal part of a template string */
%x tmpll

/* in a regular expression */
%x regex

%%
{WHITESPACES}                       { }
{CHAR_ESCAPE_SEQUENCES}             { }
{LINE_TERMINATORS}                  { BEGIN(regst); }

<INITIAL,regex,dqstr,regst,sqstr,divop>{HTML_TAG_SCRIPT_OPEN} { BEGIN(regst); return OPENING_TAG; }
{HTML_TAG_SCRIPT_CLOSE}             { BEGIN(regst); return SCRIPT_ENDED; }

       {HTML_COMMENT_OPEN}          { BEGIN(lcomm); }
       {LINE_COMMENT_START}         { BEGIN(lcomm); }
<lcomm>{LINE_COMMENT_END1}          { BEGIN(regst); }
<lcomm>{LINE_COMMENT_END2}          { BEGIN(regst); }
<lcomm>{LINE_COMMENT_END3}          { BEGIN(regst); return OPENING_TAG; }
<lcomm>{LINE_COMMENT_END4}          { BEGIN(regst); return CLOSING_TAG; }
<lcomm>{LINE_COMMENT_SKIP}          { }
<lcomm><<EOF>>                      { states_apply(); return SCRIPT_CONTINUE; }

       {BLOCK_COMMENT_START}        { BEGIN(bcomm); }
<bcomm>{BLOCK_COMMENT_END1}         { BEGIN(regst); }
<bcomm>{BLOCK_COMMENT_END2}         { BEGIN(regst); return OPENING_TAG; }
<bcomm>{BLOCK_COMMENT_END3}         { BEGIN(regst); return CLOSING_TAG; }
<bcomm>{BLOCK_COMMENT_SKIP}         { }
<bcomm><<EOF>>                      { states_apply(); return SCRIPT_CONTINUE; }

       {LITERAL_DQ_STRING_START}    { EXEC(do_spacing(LITERAL)) ECHO; BEGIN(dqstr); }
<dqstr>{LITERAL_DQ_STRING_END}      { ECHO; BEGIN(divop); }
<dqstr>{HTML_TAG_SCRIPT_CLOSE}      { BEGIN(regst); return CLOSING_TAG; }
<dqstr>\\{CR}{LF}                   { }
<dqstr>\\{LF}                       { }
<dqstr>\\{CR}                       { }
<dqstr>{LINE_TERMINATORS}           { BEGIN(regst); return BAD_TOKEN; }
<dqstr>{LITERAL_DQ_STRING_SKIP}     { ECHO; }
<dqstr>{LITERAL_DQ_STRING_TEXT}     { ECHO; }
<dqstr><<EOF>>                      { states_apply(); return SCRIPT_CONTINUE; }

       {LITERAL_SQ_STRING_START}    { EXEC(do_spacing(LITERAL)) ECHO; BEGIN(sqstr); }
<sqstr>{LITERAL_SQ_STRING_END}      { ECHO; BEGIN(divop); }
<sqstr>{HTML_TAG_SCRIPT_CLOSE}      { BEGIN(regst); return CLOSING_TAG; }
<sqstr>\\{CR}{LF}                   { }
<sqstr>\\{LF}                       { }
<sqstr>\\{CR}                       { }
<sqstr>{LINE_TERMINATORS}           { BEGIN(regst); return BAD_TOKEN; }
<sqstr>{LITERAL_SQ_STRING_SKIP}     { ECHO; }
<sqstr>{LITERAL_SQ_STRING_TEXT}     { ECHO; }
<sqstr><<EOF>>                      { states_apply(); return SCRIPT_CONTINUE; }

{OPEN_BRACKET}                      { if (!bracket_depth.empty()) bracket_depth.top()++; process_punctuator(); }
{CLOSE_BRACKET}                     { process_closing_bracket(); }

       {LITERAL_TEMPLATE_START}                  { EXEC(do_spacing(LITERAL)) ECHO; BEGIN(tmpll); }
<tmpll>(\\\\)*{LITERAL_TEMPLATE_END}             { ECHO; BEGIN(divop); }
<tmpll>(\\\\)*{LITERAL_TEMPLATE_SUBST_START}     { EXEC(process_subst_open()) }
<tmpll>{HTML_TAG_SCRIPT_CLOSE}                   { BEGIN(regst); return CLOSING_TAG; }
<tmpll>(\\\\)*\\{LITERAL_TEMPLATE_SUBST_START}   | /* escaped template substitution */
<tmpll>(\\\\)*\\{LITERAL_TEMPLATE_END}           | /* escaped backtick */
<tmpll>{LITERAL_TEMPLATE_OTHER}                  { ECHO; }
<tmpll><<EOF>>                                   { return SCRIPT_CONTINUE; }

<regst>{LITERAL_REGEX_START}        { EXEC(do_spacing(LITERAL)) yyout << '/'; states_correct(1); yyless(1); BEGIN(regex); }
<regex>{LITERAL_REGEX_END}          { ECHO; BEGIN(divop); }
<regex>{HTML_TAG_SCRIPT_CLOSE}      { BEGIN(regst); return CLOSING_TAG; }
<regex>{LITERAL_REGEX_SKIP}         { ECHO; }
<regex>\\{LF}                       |
<regex>\\{CR}                       |
<regex>{LINE_TERMINATORS}           { BEGIN(regst); return BAD_TOKEN; }
<regex>[^<{LF}{CR}{LS}{PS}\\\/]+    { ECHO; }
<regex><<EOF>>                      { states_apply(); return SCRIPT_CONTINUE; }

<divop>{DIV_OPERATOR}               |
<divop>{DIV_ASSIGNMENT_OPERATOR}    { ECHO; token = PUNCTUATOR; BEGIN(INITIAL); }

{CLOSING_BRACES}                    { ECHO; token = PUNCTUATOR; BEGIN(divop); }
{PUNCTUATOR}                        { process_punctuator(); }

{USE_STRICT_DIRECTIVE}              { EXEC(do_spacing(DIRECTIVE)) ECHO; BEGIN(INITIAL); yyout << ';'; }
{USE_STRICT_DIRECTIVE_SC}           { EXEC(do_spacing(DIRECTIVE)) ECHO; BEGIN(INITIAL); }
{KEYWORD}                           { EXEC(do_spacing(KEYWORD)) ECHO; BEGIN(regst); }
{OPERATOR}                          { EXEC(do_operator_spacing(OPERATOR)) ECHO; BEGIN(divop); }
{LITERAL}                           { EXEC(do_spacing(LITERAL)) ECHO; BEGIN(divop); }
{IDENTIFIER}                        { if (unescape(YYText())) { EXEC(do_spacing(IDENTIFIER)) EXEC(do_identifier_substitution(YYText())) } BEGIN(divop); }

.|{ALL_UNICODE}                     { ECHO; token = UNDEFINED; BEGIN(INITIAL); }
<<EOF>>                             { EEOF(eval_eof()) }

%%

// static helper functions

static std::string unicode_to_utf8(const unsigned int code)
{
    std::string res;

    if (code <= 0x7f)
        res += (char)code;
    else if (code <= 0x7ff)
    {
        res += 0xc0 | (code >> 6);
        res += 0x80 | (code & 0x3f);
    }
    else if (code <= 0xffff)
    {
        res += 0xe0 | (code >> 12);
        res += 0x80 | ((code >> 6) & 0x3f);
        res += 0x80 | (code & 0x3f);
    }

    return res;
}

static std::string unescape_unicode(const char* lexeme)
{
    assert(lexeme);

    std::string lex = lexeme;
    std::string res;

    bool is_unescape = false;
    bool is_unicode = false;
    short digits_left = 4;
    std::string unicode_str;

    for (const auto& ch : lex)
    {
        if (ch == '\\')
        {
            is_unescape = true;
            continue;
        }

        if (is_unescape)
        {
            if (ch == 'u')
            {
                is_unicode = true;
                continue;
            }
            is_unescape = false;
        }

        if (is_unicode)
        {
            unicode_str += ch;
            if (!(--digits_left))
            {
                const unsigned int unicode = std::stoi(unicode_str, nullptr, 16);
                res += unicode_to_utf8(unicode);

                unicode_str = "";
                digits_left = 4;
                is_unicode = false;
            }
            continue;
        }

        res += ch;
    }

    return res;
}

// JSTokenizer members

JSTokenizer::JSTokenizer(std::istream& in, std::ostream& out,
    JSIdentifierCtxBase& mapper, uint8_t max_template_nesting,
    char*& buf, size_t& buf_size, int cap_size)
    : yyFlexLexer(in, out),
      max_template_nesting(max_template_nesting),
      ident_ctx(mapper),
      tmp_buf(buf),
      tmp_buf_size(buf_size),
      tmp_cap_size(cap_size)
{
    BEGIN(regst);
}

JSTokenizer::~JSTokenizer()
{
    yy_delete_buffer((YY_BUFFER_STATE)tmp_buffer);
    delete[] tmp_buf;
    tmp_buf = nullptr;
    tmp_buf_size = 0;
}

void JSTokenizer::switch_to_temporal(const std::string& data)
{
    tmp.str(data);
    cur_buffer = YY_CURRENT_BUFFER;
    tmp_buffer = yy_create_buffer(tmp, data.size());
    yy_switch_to_buffer((YY_BUFFER_STATE)tmp_buffer);
}

void JSTokenizer::switch_to_initial()
{
    yy_switch_to_buffer((YY_BUFFER_STATE)cur_buffer);
    yy_delete_buffer((YY_BUFFER_STATE)tmp_buffer);
    tmp_buffer = nullptr;
}

// A return value of this method uses to terminate the scanner
// true - terminate, false - continue scanning
// Use this method only in <<EOF>> handler
// The return value should be used to make a decision about yyterminate() call
JSTokenizer::JSRet JSTokenizer::eval_eof()
{
    // If the temporal scan buffer reaches EOF, cleanup and
    // continue with the initial one
    if (tmp_buffer)
    {
        switch_to_initial();
        return EOS;
    }

    // Normal termination
    states_apply();

    return SCRIPT_CONTINUE;
}

JSTokenizer::JSRet JSTokenizer::do_spacing(JSToken cur_token)
{
    switch (token)
    {
    case PUNCTUATOR:
    case OPERATOR:
    case DIRECTIVE:
    case UNDEFINED:
        token = cur_token;
        return EOS;

    case IDENTIFIER:
    case KEYWORD:
    case LITERAL:
        yyout << ' ';
        token = cur_token;
        return EOS;
    }

    assert(false);

    return BAD_TOKEN;
}

JSTokenizer::JSRet JSTokenizer::do_operator_spacing(JSToken cur_token)
{
    switch (token)
    {
    case IDENTIFIER:
    case KEYWORD:
    case PUNCTUATOR:
    case LITERAL:
    case DIRECTIVE:
    case UNDEFINED:
        token = cur_token;
        return EOS;

    case OPERATOR:
        yyout << ' ';
        token = cur_token;
        return EOS;
    }

    assert(false);

    return BAD_TOKEN;
}

JSTokenizer::JSRet JSTokenizer::do_identifier_substitution(const char* lexeme)
{
    const char* ident = ident_ctx.substitute(lexeme);

    if (ident)
    {
        debug_logf(6, http_trace, TRACE_JS_DUMP, nullptr,
            "'%s' => '%s'\n", lexeme, ident);

        yyout << ident;
        return EOS;
    }

    debug_logf(6, http_trace, TRACE_JS_DUMP, nullptr,
        "'%s' => IDENTIFIER_OVERFLOW\n", lexeme);

    return IDENTIFIER_OVERFLOW;
}

bool JSTokenizer::unescape(const char* lexeme)
{
    if (strstr(lexeme, "\\u"))
    {
        const std::string unescaped_lex = unescape_unicode(lexeme);
        switch_to_temporal(unescaped_lex);
        return false;
    }

    return true;
}

void JSTokenizer::process_punctuator()
{
    ECHO;
    token = PUNCTUATOR;
    BEGIN(regst);
}

void JSTokenizer::process_closing_bracket()
{
    if (!bracket_depth.empty())
    {
        if (bracket_depth.top())
            bracket_depth.top()--;
        else
        {
            bracket_depth.pop();
            ECHO;
            BEGIN(tmpll);
            return;
        }
    }
    process_punctuator();
}

JSTokenizer::JSRet JSTokenizer::process_subst_open()
{
    if (bracket_depth.size() >= max_template_nesting)
        return TEMPLATE_NESTING_OVERFLOW;
    bracket_depth.push(0);
    token = PUNCTUATOR;
    ECHO;
    BEGIN(divop);
    return EOS;
}

void JSTokenizer::states_push()
{
    assert(yyleng != 0);

    sp++;
    sp %= JSTOKENIZER_MAX_STATES;
    auto& state = states[sp];

    state.token = token;
    state.length = yyleng;
    state.sc = yy_start;
}

void JSTokenizer::states_correct(int take_off)
{
    auto& state = states[sp];
    state.length -= yyleng - take_off;
}

void JSTokenizer::states_apply()
{
    int tail_size = 0;

    for (int i = JSTOKENIZER_MAX_STATES; i > 0 && tail_size < tmp_cap_size; --i)
    {
        auto idx = sp + i;
        idx %= JSTOKENIZER_MAX_STATES;
        auto& state = states[idx];

        if (state.length == 0)
            continue;

        token = state.token;
        yy_start = state.sc;
        tail_size += state.length;
        tail_size = tail_size < tmp_cap_size ? tail_size : tmp_cap_size;
    }

    for (int i = 0; i < JSTOKENIZER_MAX_STATES; ++i)
        states[i].length = 0;

    char* buf = new char[tail_size];

    yyin.seekg(-tail_size, std::ios_base::end);
    yyin.clear();
    yyin.read(buf, tail_size);

    delete[] tmp_buf;
    tmp_buf = buf;
    tmp_buf_size = tail_size;
}
