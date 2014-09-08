/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// parse_stream.cc author Russ Combs <rucombs@cisco.com>

#include "parse_stream.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <istream>
#include <sstream>
#include <string>
using namespace std;

#include "parser.h"
#include "parse_conf.h"
#include "parse_rule.h"
#include "detection/treenodes.h"

static unsigned chars = 0, tokens = 0;
static unsigned lines = 1, comments = 0;
static unsigned keys = 0, rules = 0;
static unsigned lists = 0, strings = 0;

enum TokenType
{
    TT_NONE,
    TT_PUNCT,
    TT_STRING,
    TT_LIST,
    TT_LITERAL,
    TT_MAX
};

#if 0
static const char* toks[TT_MAX] =
{
    "none", "punct", "string", "list", "literal"
};
#endif

static TokenType get_token(
    istream& is, string& s, const char* punct, bool esc)
{
    static int prev = EOF;
    int c, list, state = 0;
    s.clear();
    bool inc = true;

    if ( prev != EOF )
    {
        c = prev;
        prev = EOF;
        inc = ( c != '\n' );
    }
    else
    {
        c = is.get();
        chars++;
    }

    while ( c != EOF )
    {
        //printf("state = %d, c = %d\n", state, c);

        if ( c == '\n' )
        {
            lines++;
            if ( inc )
                inc_parse_position();
            else
                inc = true;
        }

        switch ( state )
        {
        case 0:  // idle
            if ( strchr(punct, c) )
            {
                s = c;
                return TT_PUNCT;
            }
            else if ( c == '#' )
            {
                s = c;
                comments++;
                state = 1;
            }
            else if ( c == '[' )
            {
                s += c;
                lists++;
                list = 1;
                state = 2;
            }
            else if ( c == '"' )
            {
                s += c;
                strings++;
                state = 3;
            }
            else if ( c == '!' )
            {
                s += c;
                state = 7;
            }
            else if ( c == '\\' )
            {
                state = 5;
            }
            else if ( !isspace(c) )
            {
                s += c;
                keys++;
                state = 6;
            }
            break;
        case 1:  // comment
            if ( c == '\n' )
            {
                s.clear();
                state = 0;
            }
            else if ( s.size() < 6 )
            {
                s += c;
                if ( s == "#begin" )
                    state = 8;
            }
            break;
        case 2:  // list
            s += c;
            if ( c == '[' )
                ++list;
            else if ( c == ']' )
                --list;
            if ( !list )
                return TT_LIST;
            break;
        case 3:  // string
            if ( esc && c == ';' )
            {
                prev = c;
                return TT_STRING;
            }
            s += c;
            if ( !esc && c == '"' )
            {
                return TT_STRING;
            }
            else if ( c == '\\' )
                state = 4;
            else if ( c == '\n' )
                printf("warning: line break in string on line %d\n", lines-1);
            break;
        case 4:  // quoted escape
            s += c;
            state = 3;
            break;
        case 5:  // unquoted escape
            if ( c != '\n' && c != '\r' )
                printf("error: invalid escape on line %d\n", lines);
            state = 0;
            break;
        case 6:  // token
            if ( isspace(c) || strchr(punct, c) )
            {
                prev = c;
                return TT_LITERAL;
            }
            else
                s += c;
            break;
        case 7:  // not string
            if ( c == '"' )
            {
                s += c;
                strings++;
                state = 3;
            }
            else if ( isspace(c) || strchr(punct, c) )
            {
                prev = c;
                return TT_LITERAL;
            }
            else
            {
                s += c;
                state = 6;
            }
            break;
        case 8:
            if ( c == '\n' )
            {
                s.clear();
            }
            else if ( s.size() < 4 )
            {
                s += c;
                if ( s == "#end" )
                    state = 1;
            }
            break;
        }
        c = is.get();
        chars++;
    }
    return TT_NONE;
}

enum FsmAction
{
    FSM_ACT, FSM_PRO,
    FSM_SIP, FSM_SP, 
    FSM_DIR, 
    FSM_DIP, FSM_DP,
    FSM_STB, FSM_SOB,
    FSM_EOB, 
    FSM_KEY, FSM_OPT,
    FSM_VAL, FSM_SET,
    FSM_ADD, FSM_INC,
    FSM_END,
    FSM_NOP, FSM_ERR, 
    FSM_MAX
};

const char* acts[FSM_MAX] =
{
    "act", "pro",
    "sip", "sp",
    "dir",
    "dip", "dp",
    "stb", "sob",
    "eob",
    "key", "opt",
    "val", "set",
    "add", "inc",
    "end",
    "nop", "err"
};

struct State
{
    int num;
    int next;
    TokenType type;
    FsmAction action;
    const char* match;
    const char* punct;
};

static const State fsm[] =
{
    { -1,  0, TT_NONE,    FSM_ERR, nullptr,    ""      },
    {  0, 15, TT_LITERAL, FSM_KEY, "include",  ""      },
    {  0,  1, TT_LITERAL, FSM_ACT, nullptr,    "("     },
    {  1,  8, TT_PUNCT,   FSM_STB, "(",        "(:,;)" },
    {  1,  2, TT_LITERAL, FSM_PRO, nullptr,    ""      },
    {  2,  3, TT_LIST,    FSM_SIP, nullptr,    nullptr },
    {  2,  3, TT_LITERAL, FSM_SIP, nullptr,    nullptr },
    {  3,  4, TT_LIST,    FSM_SP,  nullptr,    nullptr },
    {  3,  4, TT_LITERAL, FSM_SP,  nullptr,    nullptr },
    {  4,  5, TT_LITERAL, FSM_DIR, nullptr,    nullptr },
    {  5,  6, TT_LIST,    FSM_DIP, nullptr,    nullptr },
    {  5,  6, TT_LITERAL, FSM_DIP, nullptr,    nullptr },
    {  6,  7, TT_LIST,    FSM_DP,  nullptr,    "(:,;)" },
    {  6,  7, TT_LITERAL, FSM_DP,  nullptr,    "(:,;)" },
    {  7,  8, TT_PUNCT,   FSM_SOB, "(",        nullptr },
    {  8,  0, TT_PUNCT,   FSM_EOB, ")",        nullptr },
    {  8, 13, TT_LITERAL, FSM_KEY, "metadata", nullptr },
    {  8, 13, TT_LITERAL, FSM_KEY, "reference",":,;"   },
    {  8,  9, TT_LITERAL, FSM_KEY, nullptr,    nullptr },
    {  9,  8, TT_PUNCT,   FSM_END, ";",        nullptr },
    {  9, 10, TT_PUNCT,   FSM_NOP, ":",        nullptr },
    // we can't allow this because the syntax is squiffy
    // would prefer to require a ; after the last option
    // (and delete all the other cases like this too)
    //{  9,  0, TT_PUNCT,   FSM_EOB, ")",        ""      },
    { 10, 12, TT_STRING,  FSM_OPT, nullptr,    nullptr },
    { 10, 11, TT_LITERAL, FSM_OPT, nullptr,    nullptr },
    { 11, 12, TT_STRING,  FSM_VAL, nullptr,    nullptr },
    { 11, 12, TT_LITERAL, FSM_VAL, nullptr,    nullptr },
    { 11,  8, TT_PUNCT,   FSM_END, ";",        nullptr },
    { 11,  0, TT_PUNCT,   FSM_EOB, ")",        ""      },
    { 11, 10, TT_PUNCT,   FSM_SET, ",",        nullptr },
    { 12,  8, TT_PUNCT,   FSM_END, ";",        nullptr },
    { 12,  0, TT_PUNCT,   FSM_EOB, ")",        ""      },
    { 12, 10, TT_PUNCT,   FSM_SET, ",",        nullptr },
    { 13, 14, TT_PUNCT,   FSM_NOP, ":",        nullptr },
    { 14,  8, TT_PUNCT,   FSM_END, ";",        "(:,;)" },
    { 14, 14, TT_NONE,    FSM_SET, ",",        nullptr },
    { 14, 14, TT_NONE,    FSM_ADD, nullptr,    nullptr },
    { 15,  0, TT_LITERAL, FSM_INC, nullptr,    nullptr },
};

static const State* get_state(int num, TokenType type, const string& tok)
{
    const unsigned sz = sizeof(fsm)/sizeof(fsm[0]);

    for ( unsigned i = 0; i < sz; i++ )
    {
        const State* s = fsm + i;

        if (
            (num == s->num) &&
            (!s->type || type == s->type) &&
            (!s->match || tok == s->match) )
        {
            return fsm + i;
        }
    }
    ParseError("syntax error");
    return fsm;
}

struct RuleParseState
{
    RuleTreeNode rtn;
    OptTreeNode* otn;

    string key;
    string opt;
    string val;

    bool tbd;

    RuleParseState()
    { otn = nullptr; };
};

static void parse_body(const char*, RuleParseState&, struct SnortConfig*);

static bool exec(
    FsmAction act, string& tok,
    RuleParseState& rps, SnortConfig* sc)
{
    switch ( act )
    {
    case FSM_ACT:
        //printf("\nparse act = %s\n", tok.c_str());
        if ( tok == "END" )
            return true;
        parse_rule_type(sc, tok.c_str(), rps.rtn);
        break;
    case FSM_PRO:
        //printf("parse pro = %s\n", tok.c_str());
        parse_rule_proto(sc, tok.c_str(), rps.rtn);
        break;
    case FSM_SIP:
        //printf("parse sip = %s\n", tok.c_str());
        parse_rule_nets(sc, tok.c_str(), true, rps.rtn);
        break;
    case FSM_SP:
        //printf("parse sp = %s\n", tok.c_str());
        parse_rule_ports(sc, tok.c_str(), true, rps.rtn);
        break;
    case FSM_DIR:
        //printf("parse dir = %s\n", tok.c_str());
        parse_rule_dir(sc, tok.c_str(), rps.rtn);
        break;
    case FSM_DIP:
        //printf("parse dip = %s\n", tok.c_str());
        parse_rule_nets(sc, tok.c_str(), false, rps.rtn);
        break;
    case FSM_DP:
        //printf("parse dp = %s\n", tok.c_str());
        parse_rule_ports(sc, tok.c_str(), false, rps.rtn);
        break;
    case FSM_STB:
        rps.otn = parse_rule_open(sc, rps.rtn, true);
        break;
    case FSM_SOB:
        rps.otn = parse_rule_open(sc, rps.rtn);
        break;
    case FSM_EOB:
    {
        if ( rps.tbd )
            exec(FSM_END, tok, rps, sc);
        const char* extra = parse_rule_close(sc, rps.rtn, rps.otn);
        if ( extra )
            parse_body(extra, rps, sc);
        else
        {
            rps.otn = nullptr;
            rules++;
        }
        break;
    }
    case FSM_KEY:
        if ( tok != "include" )
            parse_rule_opt_begin(sc, tok.c_str());
        rps.key = tok;
        rps.opt.clear();
        rps.val.clear();
        rps.tbd = true;
        break;
    case FSM_OPT:
        rps.opt = tok;
        rps.val.clear();
        rps.tbd = true;
        break;
    case FSM_VAL:
        rps.val = tok;
        rps.tbd = true;
        break;
    case FSM_SET:
        //printf("parse %s:%s = %s\n", rps.key.c_str(), rps.opt.c_str(), rps.val.c_str());
        parse_rule_opt_set(sc, rps.key.c_str(), rps.opt.c_str(), rps.val.c_str());
        rps.opt.clear();
        rps.val.clear();
        rps.tbd = false;
        break;
    case FSM_END:
        //printf("parse %s:%s = %s\n", rps.key.c_str(), rps.opt.c_str(), rps.val.c_str());
        if ( rps.opt.size() )
            parse_rule_opt_set(sc, rps.key.c_str(), rps.opt.c_str(), rps.val.c_str());
        parse_rule_opt_end(sc, rps.key.c_str(), rps.otn);
        rps.opt.clear();
        rps.val.clear();
        rps.tbd = false;
        break;
    case FSM_ADD:
        // adding another state would eliminate this if
        if ( rps.opt.empty() )
            rps.opt += tok;
        else
        {
            if ( rps.val.size() )
                rps.val += " ";
            rps.val += tok;
        }
        rps.tbd = true;
        break;
    case FSM_INC:
        //printf("\nparse %s = %s\n", rps.key.c_str(), tok.c_str());
        parse_include(sc, tok.c_str());
        break;
    case FSM_NOP:
        break;
    case FSM_ERR:
        //printf("error\n");
    default:
        break;
    }
    return false;
}

// parse_body() is called at the end of a stub rule to parse the detection
// options in an so rule.  similar to parse_stream() except we start in a
// different state.
static void parse_body(const char* extra, RuleParseState& rps, struct SnortConfig* sc)
{
    stringstream is(extra);

    string tok;
    TokenType type;
    bool esc = false;

    int num = 8;
    const char* punct = "(:,;)";

    while ( (type = get_token(is, tok, punct, esc)) )
    {
        ++tokens;
        const State* s = get_state(num, type, tok);

        exec(s->action, tok, rps, sc);

        num = s->next;
        esc = (rps.key == "pcre");

        if ( s->punct )
            punct = s->punct;
    }
}

void parse_stream(istream& is, struct SnortConfig* sc)
{
    string tok;
    TokenType type;
    bool esc = false;

    int num = 0;
    const char* punct = fsm[0].punct;
    RuleParseState rps;

    while ( (type = get_token(is, tok, punct, esc)) )
    {
        ++tokens;
        const State* s = get_state(num, type, tok);

        //printf("%d: %s = '%s' -> %s\n",
        //    num, toks[type], tok.c_str(), acts[s->action]);

        if ( exec(s->action, tok, rps, sc) )
            break;

        num = s->next;
        esc = (rps.key == "pcre");

        if ( s->punct )
            punct = s->punct;
    }
    if ( num )
        ParseError("incomplete rule");

    //printf("chars = %d, tokens = %d\n", chars, tokens);
    //printf("lines = %d, comments = %d\n", lines, comments);
    //printf("rules = %d, keys = %d\n", rules, keys);
    //printf("lists = %d, strings = %d\n", lists, strings);
}

