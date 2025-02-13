//--------------------------------------------------------------------------
// Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
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

// parse_so_rule.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parse_so_rule.h"

#include <cctype>
#include <set>
#include <string>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

class SoRuleParser
{
public:
    SoRuleParser() = default;

    bool parse_so_rule(const char* in, std::string& stub, std::string& opts);

private:
    bool is_stub_option(std::string& opt);
    void trim(std::string&);
};

static std::set<std::string> stub_opts =
{
    "classtype", "flowbits", "gid", "metadata", "msg", "priority",
    "reference", "rem", "rev", "service", "sid", "soid"
};

bool SoRuleParser::is_stub_option(std::string& opt)
{
    size_t n = opt.find_first_of(" :;");
    std::string name = opt.substr(0, n);
    return stub_opts.find(name) != stub_opts.end();
}

// split rule into stub and detection options
//
// the FSM deletes duplicate spaces between options except in these cases:
// -- start of rule:  "^ alert"
// -- middle of rule: ";      " (indent following # comment)
// -- end of rule:    ";     )" (multiple detection opts)
//
// the trim method below cleans up the start/end of rule cases
// FIXIT-L the middle of rule case should be handled by the FSM

bool SoRuleParser::parse_so_rule(const char* in, std::string& stub, std::string& opts)
{
    unsigned state = 0;
    unsigned next = 0;

    char prev = '\0';
    bool drop = false;

    std::string opt;
    std::string* accum = &stub;

    while ( *in )
    {
        char c = *in;

        switch ( state )
        {
        case 0:  // in rule header
            if ( c == '#' )
            {
                state = 1;
                next = 0;
                drop = true;
                break;
            }
            else if ( c == '(' )
                state = 5;
            else if ( c == '/' )
            {
                state = 2;
                next = 0;
                drop = true;
            }
            break;
        case 1:  // in bash-style comment
            if ( c == '\n' )
            {
                state = next;
                drop = false;
                c = ' ';
            }
            break;
        case 2:  // in C-style comment begin
            if ( c == '*' )
                state = 3;
            else
            {
                *accum += '/';
                state = next;
                drop = false;
                continue; // repeat
            }
            break;
        case 3:  // in C-style comment
            if ( c == '*' )
                state = 4;
            break;
        case 4:  // in C-style comment end
            if ( c == '/' )
            {
                state = next;
                drop = false;
                c = ' ';
            }
            else
                state = 3;
            break;
        case 5:  // in rule ( body )
            if ( c == '#' )
            {
                state = 1;
                next = 5;
                drop = true;
                break;
            }
            else if ( c == '/' )
            {
                state = 2;
                next = 5;
                drop = true;
            }
            else if ( c == ')' )
            {
                *accum += c;
                trim(stub);
                return true;
            }
            else if ( !std::isspace(c) )
            {
                opt.clear();
                accum = &opt;
                state = 6;
            }
            break;
        case 6:  // in rule option
            // FIXIT-L ideally we'd allow # comments within so rule stub options
            // same as we do for non stubs but we should reuse the text rule parser
            // instead of building this out.  supporting them here is non-trivial
            // (like state 5) because references can have # fragments.
            if ( c == '/' )
            {
                state = 2;
                next = 6;
                drop = true;
            }
            else if ( c == '"' )
            {
                state = 7;
            }
            else if ( c == ';' )
            {
                accum = &stub;
                state = 5;

                if ( is_stub_option(opt) )
                    stub += opt;
                else
                {
                    opts += opt;
                    opts += *in++;
                    continue;
                }
            }
            break;
        case 7:  // in "string"
            if ( c == '\\' )
                state = 8;
            else if ( c == '"' )
                state = 6;
            break;
        case 8:  // in escape
            state = 7;
            break;
        }
        if ( state < 7 and c == '\n' )
            c = ' ';

        if ( (!drop and (!std::isspace(c) or !std::isspace(prev))) or (state >= 6) )
        {
            *accum += c;
            if ( *accum == stub )
                prev = c;
        }
        ++in;
    }

    return false;
}

void SoRuleParser::trim(std::string& stub)
{
    while ( std::isspace(stub[0]) )
        stub.erase(0, 1);

    size_t n = stub.rfind(';');

    if ( n != std::string::npos and ++n < stub.length() and std::isspace(stub[n]) )
    {
        ++n;
        while ( n < stub.length() and std::isspace(stub[n]) )
            stub.erase(n, 1);
    }
}

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

bool get_so_stub(const char* in, std::string& stub)
{
    SoRuleParser sop;
    std::string opts;
    return sop.parse_so_rule(in, stub, opts);
}

//--------------------------------------------------------------------------
// test data
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
struct TestCase
{
    const char* rule;
    const char* expect;
    bool result;
};

static const TestCase syntax_tests[] =
{
    { "alert()", "alert()", true },
    { " alert() ", "alert()", true },

    { "#alert()", "", false },
    { "# \nalert()", "alert()", true },
    { "alert#\n()", "alert ()", true },
    { "alert() # comment", "alert()", true },
    { "alert(#\n)", "alert( )", true },
    { "alert(#)", "alert(", false },
    { "alert()#", "alert()", true },

    { "/*alert()*/", " ", false },
    { "/ *alert()*/", "/ *alert()", true },
    { "/* /alert()", "", false },
    { "/* *alert()", "", false },
    { "/*alert(*/)", " )", false },
    { "alert(/*)", "alert(", false },
    { "alert(/*)*/", "alert( ", false },
    { "alert(/**)/", "alert(", false },
    { "alert/*()*/", "alert ", false },
    { "alert/*(*/)", "alert )", false },

    { "alert(/**/) ", "alert( )", true },
    { "alert( /**/) ", "alert( )", true },
    { "alert(/**/ ) ", "alert( )", true },
    { "alert( /**/ ) ", "alert( )", true },
    { "alert(/* comment */)", "alert( )", true },

    { nullptr, nullptr, false }
};

static const TestCase basic_tests[] =
{
    { "alert( sid:1; )", "alert( sid:1; )", true },

    { "alert( sid:1 /*comment*/; )", "alert( sid:1  ; )", true },
    // ideally below would be supported, but above works
    { "alert( sid:1 # comment\n; )", "alert( sid:1 # comment ; )", true },
    { "alert( sid:1; /*id:0;*/ )", "alert( sid:1; )", true },

    { "alert tcp any any -> any any ( )",
      "alert tcp any any -> any any ( )", true },

    { "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ( )",
      "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ( )", true },

    { nullptr, nullptr, false }
};

// __STRDUMP_DISABLE__
static const TestCase stub_tests[] =
{
    { "alert( id:0; )", "alert( )", true },
    { "alert( sid:1; id:0; )", "alert( sid:1; )", true },
    { "alert( sid:1;id:0; )", "alert( sid:1; )", true },
    { "alert( id:0;sid:1; )", "alert( sid:1; )", true },

    { "alert( id:/*comment*/0; )", "alert( )", true },
    { "alert( id: #comment\n0; )", "alert( )", true },

    { R"_(alert( content:"foo"; ))_", "alert( )", true },
    { R"_(alert( content:"f;o"; ))_", "alert( )", true },
    { R"_(alert( content:"f\"o"; ))_", "alert( )", true },

    { R"_(alert( soid; rem:"soid"; /*soid*/ ))_",
      R"_(alert( soid; rem:"soid"; ))_", true },

    { R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; flow:to_server,established; http_uri; content:"/j.php|3F|u|3D|", fast_pattern,nocase; content:"&v=f2&r=",depth 8,offset 41,nocase; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; service:http; reference:url,www.virustotal.com/file/bff436d8a2ccf1cdce56faabf341e97f59285435b5e73f952187bbfaf4df3396/analysis/; classtype:trojan-activity; sid:24062; rev:7; ))_",
      R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; service:http; reference:url,www.virustotal.com/file/bff436d8a2ccf1cdce56faabf341e97f59285435b5e73f952187bbfaf4df3396/analysis/; classtype:trojan-activity; sid:24062; rev:7; ))_",
      true },

    { nullptr, nullptr, false }
};
// __STRDUMP_ENABLE__

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

TEST_CASE("parse_so_rule.syntax", "[parser]")
{
    const TestCase* tc = syntax_tests;

    while ( tc->rule )
    {
        SoRuleParser sop;
        std::string stub;
        std::string opts;
        bool parse = sop.parse_so_rule(tc->rule, stub, opts);
        CHECK(tc->result == parse);
        CHECK(tc->expect == stub);
        ++tc;
    }
}

TEST_CASE("parse_so_rule.basic", "[parser]")
{
    const TestCase* tc = basic_tests;

    while ( tc->rule )
    {
        SoRuleParser sop;
        std::string stub;
        std::string opts;
        bool parse = sop.parse_so_rule(tc->rule, stub, opts);
        CHECK(tc->result == parse);
        CHECK(tc->expect == stub);
        ++tc;
    }
}

TEST_CASE("get_so_stub", "[parser]")
{
    const TestCase* tc = stub_tests;

    while ( tc->rule )
    {
        std::string stub;
        bool get = get_so_stub(tc->rule, stub);
        CHECK(tc->result == get);
        CHECK(tc->expect == stub);
        ++tc;
    }
}

#endif

