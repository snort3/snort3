//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// parse_stream.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parse_stream.h"

#include <sstream>

#include "log/messages.h"
#include "managers/ips_manager.h"

#include "parser.h"
#include "parse_conf.h"
#include "parse_rule.h"

using namespace snort;
using namespace std;

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

//#define TRACER
#ifdef TRACER
static const char* const toks[TT_MAX] =
{
    "none", "punct", "string", "list", "literal"
};
#endif

static char unescape(char c)
{
    switch ( c )
    {
    case 'a': return '\a';
    case 'b': return '\b';
    case 'f': return '\f';
    case 'n': return '\n';
    case 'r': return '\r';
    case 't': return '\t';
    case 'v': return '\v';
    }
    return c;
}

static uint8_t to_hex(char c)
{
    if ( isdigit(c) )
        return c - '0';
    else if ( isupper(c) )
        return 10 + c - 'A';
    else
        return 10 + c - 'a';
}

static TokenType get_token(
    istream& is, string& s, const char* punct, int esc)
{
    static int prev = EOF;
    int c, list = 0, state = 0;
    s.clear();
    bool inc = true;
    static int pos = 0;
    uint8_t hex = 0;

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
#ifdef TRACER
        printf("state = %d, c = %d\n", state, c);
#endif

        if ( c == '\n' )
        {
            lines++;
            pos = 0;

            if ( inc )
                inc_parse_position();
            else
                inc = true;
        }
        else
            pos++;

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
            else if ( c == '/' )
            {
                s = c;
                state = 10;
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
                if ( pos == 6 && !strcasecmp(s.c_str(), "#begin") )
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
            if ( esc && c == '"' )
            {
                s += c;
                return TT_STRING;
            }
            if ( !esc && c == ';' )
            {
                prev = c;
                return TT_STRING;
            }
            else if ( c == '\\' )
                state = (esc > 0) ? 4 : 16;
            else if ( c == '\n' )
                ParseWarning(WARN_RULES, "line break in string on line %u\n", lines-1);
            else
                s += c;
            break;
        case 4:  // quoted escape
            if ( c == 'x' )
                state = 14;
            else
            {
                s += unescape(c);
                state = 3;
            }
            break;
        case 5:  // unquoted escape
            if ( c != '\n' && c != '\r' )
                ParseWarning(WARN_RULES, "invalid escape on line %u\n", lines);
            state = 0;
            break;
        case 6:  // token
            if ( esc && c == '\\' )
            {
                state = 9;
            }
            else if ( isspace(c) || strchr(punct, c) )
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
                if ( !strcasecmp(s.c_str(), "#end") )
                    state = 1;
            }
            break;
        case 9:  // token escape
            s += c;
            state = 6;
            break;
        case 10:  // start of comment?
            if ( c == '*' )
            {
                s.clear();
                state = 11;
                break;
            }
            keys++;
            // now as if state == 6
            if ( esc && c == '\\' )
            {
                state = 9;
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
        case 11:  // /* comment */
            if ( c == '*' )
                state = 12;
            else if ( c == '"' )
                state = 13;
            break;
        case 12:  // end of comment?
            if ( c == '/' )
            {
                comments++;
                state = 0;
            }
            break;
        case 13:  // quoted string in comment
            if ( c == '"' )
                state = 11;
            else if ( c == '\n' )
            {
                ParseWarning(WARN_RULES, "line break in commented string on line %u\n", lines-1);
                state = 11;
            }
            break;
        case 14:  // escaped hex in string - first digit
            if ( isxdigit(c) )
            {
                hex = to_hex(c);
                state = 15;
            }
            else
            {
                ParseWarning(WARN_RULES, "\\x used with no following hex digits on line %u\n",
                        lines-1);
                s += c;
                state = 3;
            }
            break;
        case 15:  // escaped hex in string - second digit
            if ( isxdigit(c) )
            {
                hex <<= 4;
                hex |= to_hex(c);
                s += hex;
                state = 3;
            }
            else
            {
                s += hex;
                s += c;
                state = 3;
            }
            break;
        case 16:  // string we don't unescape
            s += '\\';
            s += c;
            state = 3;
            break;
        }
        c = is.get();
        chars++;
    }
    return TT_NONE;
}

enum FsmAction
{
    FSM_ACT, FSM_PRO,FSM_HDR,
    FSM_SIP, FSM_SP, FSM_SPX,
    FSM_DIR,
    FSM_DIP, FSM_DP, FSM_DPX,
    FSM_SOB, FSM_STB,
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
    { -1, 0, TT_NONE,    FSM_ERR, nullptr,    "" },
    { 0, 15, TT_LITERAL, FSM_KEY, "include",  "" },
    { 0,  1, TT_LITERAL, FSM_ACT, nullptr,    "(" },
    { 1,  8, TT_PUNCT,   FSM_STB, "(",        "(:,;)" },
    { 1,  2, TT_LITERAL, FSM_PRO, nullptr,    "(" },
    { 2,  8, TT_PUNCT,   FSM_HDR, "(",        "(:,;)" },
    { 2,  3, TT_LIST,    FSM_SIP, nullptr,    "" },
    { 2,  3, TT_LITERAL, FSM_SIP, nullptr,    "" },
    { 3,  5, TT_LITERAL, FSM_SPX, "->",       nullptr },
    { 3,  5, TT_LITERAL, FSM_SPX, "<>",       nullptr },
    { 3,  4, TT_LIST,    FSM_SP,  nullptr,    nullptr },
    { 3,  4, TT_LITERAL, FSM_SP,  nullptr,    nullptr },
    { 4,  5, TT_LITERAL, FSM_DIR, nullptr,    nullptr },
    { 5,  6, TT_LIST,    FSM_DIP, nullptr,    "(" },
    { 5,  6, TT_LITERAL, FSM_DIP, nullptr,    "(" },
    { 6,  8, TT_PUNCT,   FSM_DPX, "(",        "(:,;)" },
    { 6,  7, TT_LIST,    FSM_DP,  nullptr,    "(:,;)" },
    { 6,  7, TT_LITERAL, FSM_DP,  nullptr,    "(:,;)" },
    { 7,  8, TT_PUNCT,   FSM_SOB, "(",        nullptr },
    { 8,  0, TT_PUNCT,   FSM_EOB, ")",        nullptr },
    { 8, 13, TT_LITERAL, FSM_KEY, "metadata", nullptr },
    { 8, 16, TT_LITERAL, FSM_KEY, "reference",":;" },
    { 8,  9, TT_LITERAL, FSM_KEY, nullptr,    nullptr },
    { 9,  8, TT_PUNCT,   FSM_END, ";",        nullptr },
    { 9, 10, TT_PUNCT,   FSM_NOP, ":",        nullptr },
    // we can't allow this because the syntax is squiffy
    // would prefer to require a ; after the last option
    // (and delete all the other cases like this too)
    //{  9,  0, TT_PUNCT,   FSM_EOB, ")",        ""      },
    { 10, 12, TT_STRING,  FSM_OPT, nullptr,    nullptr },
    { 10, 11, TT_LITERAL, FSM_OPT, nullptr,    nullptr },
    { 11, 12, TT_STRING,  FSM_VAL, nullptr,    nullptr },
    { 11, 12, TT_LITERAL, FSM_VAL, nullptr,    nullptr },
    { 11,  8, TT_PUNCT,   FSM_END, ";",        nullptr },
    { 11,  0, TT_PUNCT,   FSM_EOB, ")",        "" },
    { 11, 10, TT_PUNCT,   FSM_SET, ",",        nullptr },
    { 12,  8, TT_PUNCT,   FSM_END, ";",        nullptr },
    { 12,  0, TT_PUNCT,   FSM_EOB, ")",        "" },
    { 12, 10, TT_PUNCT,   FSM_SET, ",",        nullptr },
    { 13, 14, TT_PUNCT,   FSM_NOP, ":",        nullptr },
    { 14,  8, TT_PUNCT,   FSM_END, ";",        "(:,;)" },
    { 14, 14, TT_NONE,    FSM_SET, ",",        nullptr },
    { 14, 14, TT_NONE,    FSM_ADD, nullptr,    nullptr },
    { 15,  0, TT_LITERAL, FSM_INC, nullptr,    nullptr },
    { 16, 14, TT_PUNCT,   FSM_NOP, ":",        ";" },
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
            return s;
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
    { otn = nullptr; }
};

static void parse_body(const char*, RuleParseState&, struct snort::SnortConfig*);

static bool exec(
    FsmAction act, string& tok,
    RuleParseState& rps, snort::SnortConfig* sc)
{
    switch ( act )
    {
    case FSM_ACT:
        // FIXIT-L if non-rule tok != "END", parsing goes bad
        // (need ctl-D to terminate)
        if ( tok == "END" )
            return true;
        parse_rule_type(sc, tok.c_str(), rps.rtn);
        break;
    case FSM_PRO:
        parse_rule_proto(sc, tok.c_str(), rps.rtn);
        break;
    case FSM_HDR:
        parse_rule_nets(sc, "any", true, rps.rtn);
        parse_rule_ports(sc, "any", true, rps.rtn);
        parse_rule_dir(sc, "->", rps.rtn);
        parse_rule_nets(sc, "any", false, rps.rtn);
        parse_rule_ports(sc, "any", false, rps.rtn);
        rps.otn = parse_rule_open(sc, rps.rtn);
        break;
    case FSM_SIP:
        parse_rule_nets(sc, tok.c_str(), true, rps.rtn);
        break;
    case FSM_SP:
        parse_rule_ports(sc, tok.c_str(), true, rps.rtn);
        break;
    case FSM_SPX:
        parse_rule_ports(sc, "any", true, rps.rtn);
        // fall thru ...
    case FSM_DIR:
        parse_rule_dir(sc, tok.c_str(), rps.rtn);
        break;
    case FSM_DIP:
        parse_rule_nets(sc, tok.c_str(), false, rps.rtn);
        break;
    case FSM_DP:
        parse_rule_ports(sc, tok.c_str(), false, rps.rtn);
        break;
    case FSM_DPX:
        parse_rule_ports(sc, "any", false, rps.rtn);
        // fall thru ...
    case FSM_SOB:
        rps.otn = parse_rule_open(sc, rps.rtn);
        break;
    case FSM_STB:
        rps.otn = parse_rule_open(sc, rps.rtn, true);
        break;
    case FSM_EOB:
    {
        if ( rps.tbd )
            exec(FSM_END, tok, rps, sc);

        if ( const char* extra = parse_rule_close(sc, rps.rtn, rps.otn) )
        {
            IpsManager::reset_options();
            parse_body(extra, rps, sc);
        }
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
        parse_rule_opt_set(sc, rps.key.c_str(), rps.opt.c_str(), rps.val.c_str());
        rps.opt.clear();
        rps.val.clear();
        rps.tbd = false;
        break;
    case FSM_END:
        if ( !rps.opt.empty() )
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
            if ( !rps.val.empty() )
                rps.val += " ";
            rps.val += tok;
        }
        rps.tbd = true;
        break;
    case FSM_INC:
        parse_include(sc, tok.c_str());
        break;
    case FSM_NOP:
        break;
    case FSM_ERR:
    default:
        break;
    }
    return false;
}

// FIXIT-L escaping should not be by option name
// probably should remove content escaping except for \" so
// that individual rule options can do whatever
static int get_escape(const string& s)
{
    if ( s == "pcre" )
        return 0;  // no escape, option goes to ;

    else if ( s == "regex" || s == "sd_pattern" )
        return -1; // no escape, option goes to "

    return 1;      // escape, option goes to "
}

// parse_body() is called at the end of a stub rule to parse the detection
// options in an so rule.  similar to parse_stream() except we start in a
// different state.
static void parse_body(const char* extra, RuleParseState& rps, snort::SnortConfig* sc)
{
    stringstream is(extra);

    string tok;
    TokenType type;
    int esc = 1;

    int num = 8;
    const char* punct = "(:,;)";

    while ( (type = get_token(is, tok, punct, esc)) )
    {
        ++tokens;
        const State* s = get_state(num, type, tok);

#ifdef TRACER
        printf("%d: %s = '%s' -> %s\n",
            num, toks[type], tok.c_str(), acts[s->action]);
#endif
        exec(s->action, tok, rps, sc);

        num = s->next;
        esc = get_escape(rps.key);

        if ( s->punct )
            punct = s->punct;
    }
}

void parse_stream(istream& is, snort::SnortConfig* sc)
{
    string tok;
    TokenType type;
    int esc = 1;

    int num = 0;
    const char* punct = fsm[0].punct;
    RuleParseState rps;

    while ( (type = get_token(is, tok, punct, esc)) )
    {
        ++tokens;
        const State* s = get_state(num, type, tok);

#ifdef TRACER
        printf("%d: %s = '%s' -> %s\n",
            num, toks[type], tok.c_str(), acts[s->action]);
#endif

        if ( exec(s->action, tok, rps, sc) )
            break;

        num = s->next;
        esc = get_escape(rps.key);

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

