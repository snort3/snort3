//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

// must parse out stub options for --dump-dynamic-rules
// must parse out detection options (ie everything else) after loading stub
//
// for plain so rules, all options are in stub
// for protected rules, stub options depend on the use of UNORDERED_OPTS
//
// assume valid rule syntax
// handles # and /* */ comments
// return true if parsed rule body close
// no requirement to beautify ugly rules

class SoRuleParser
{
public:
    SoRuleParser(bool p)
    { is_plain = p; }

    bool parse_so_rule(const char* in, std::string& stub, std::string& opts);

private:
    bool is_stub_option(std::string& opt);

private:
    bool in_stub;
    bool is_plain;
};

//#define UNORDERED_OPTS
#ifdef UNORDERED_OPTS
// these options are shown in so rule stubs
// any other option is considered a detection option
static std::set<std::string> stub_opts =
{
    "classtype", "flowbits", "gid", "metadata", "msg", "priority",
    "reference", "rem", "rev", "service", "sid", "soid"
};

bool SoRuleParser::is_stub_option(std::string& opt)
{
    if ( is_plain )
        return true;

    size_t n = opt.find_first_of(" :;");
    std::string name = opt.substr(0, n);
    return stub_opts.find(name) != stub_opts.end();
}
#else
// all options up to and including soid are shown in so rule stubs
// any options following soid are considered detection options
// this approach requires Talos to reorder rule options so is not
// viable long-term.
bool SoRuleParser::is_stub_option(std::string& opt)
{
    if ( is_plain )
        return true;

    if ( !in_stub )
        return false;

    size_t n = opt.find_first_of(" :;");
    std::string name = opt.substr(0, n);

    if  ( name == "soid" )
    {
        in_stub = false;
        return true;
    }
    return true;
}
#endif

// split rule into stub and detection options
bool SoRuleParser::parse_so_rule(const char* in, std::string& stub, std::string& opts)
{
    in_stub = true;

    int state = 0;
    int next = 0;

    bool del_sp = false;

    std::string opt;
    std::string* accum = &stub;

    while ( *in )
    {
        switch ( state )
        {
        case 0:
            if ( *in == '#' )
            {
                state = 1;
                next = 0;
                break;
            }
            else if ( *in == '(' )
                state = 5;
            else if ( *in == '/' )
            {
                state = 2;
                next = 0;
            }
            break;
        case 1:
            if ( *in == '\n' )
                state = next;
            break;
        case 2:
            if ( *in == '*' )
                state = 3;
            else
            {
                state = next;
                continue; // repeat
            }
            break;
        case 3:
            if ( *in == '*' )
                state = 4;
            break;
        case 4:
            if ( *in == '/' )
                state = next;
            else
                state = 3;
            break;
        case 5:
            if ( del_sp )
            {
                if ( std::isspace(*in) )
                {
                    opts += *in++;
                    continue;
                }
                else
                    del_sp = false;
            }
            if ( *in == '#' )
            {
                state = 1;
                next = 5;
                break;
            }
            else if ( *in == '/' )
            {
                state = 2;
                next = 5;
            }
            else if ( *in == ')' )
            {
                *accum += *in;
                return true;
            }
            else if ( !std::isspace(*in) )
            {
                opt.clear();
                accum = &opt;
                state = 6;
            }
            break;
        case 6:
            if ( *in == '#' )
            {
                state = 1;
                next = 6;
                break;
            }
            else if ( *in == '/' )
            {
                state = 2;
                next = 6;
            }
            else if ( *in == '"' )
            {
                state = 7;
            }
            else if ( *in == ';' )
            {
                accum = &stub;
                state = 5;
                
                if ( is_stub_option(opt) )
                    stub += opt;
                else
                {
                    opts += opt;
                    opts += *in++;
                    del_sp = true;
                    continue;
                }
            }
            break;
        case 7:
            if ( *in == '\\' )
                state = 8;
            else if ( *in == '"' )
                state = 6;
            break;
        case 8:
            state = 7;
            break;
        }
        *accum += *in++;
    }

    return false;
}

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

bool get_so_stub(const char* in, bool plain, std::string& stub)
{
    SoRuleParser sop(plain);
    std::string opts;
    return sop.parse_so_rule(in, stub, opts);
}

bool get_so_options(const char* in, bool plain, std::string& opts)
{
    SoRuleParser sop(plain);
    std::string stub;
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
    { "alert() ", "alert()", true },

    { "alert tcp any any -> any any ( )", 
      "alert tcp any any -> any any ( )", true },

    { "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ( )", 
      "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ( )", true },

    { "#alert()", "#alert()", false },
    { "# \nalert()", "# \nalert()", true },
    { "alert#\n()", "alert#\n()", true },
    { "alert() # comment", "alert()", true },
    { "alert(#\n)", "alert(#\n)", true },
    { "alert(#)", "alert(#)", false },

    { "/*alert()*/", "/*alert()*/", false },
    { "/ *alert()*/", "/ *alert()", true },
    { "/* /alert()", "/* /alert()", false },
    { "/* *alert()", "/* *alert()", false },
    { "/*alert(*/)", "/*alert(*/)", false },
    { "alert(/*)", "alert(/*)", false },
    { "alert(/*)*/", "alert(/*)*/", false },
    { "alert(/**)/", "alert(/**)/", false },
    { "alert/*()*/", "alert/*()*/", false },
    { "alert/*(*/)", "alert/*(*/)", false },

    { "alert(/**/) ", "alert(/**/)", true },
    { "alert(/* sid:1; */)", "alert(/* sid:1; */)", true },

    { "alert( sid:1; )", "alert( sid:1; )", true },

    { "alert( sid:1 /*comment*/; )", "alert( sid:1 /*comment*/; )", true },
    { "alert( sid:1 # comment\n; )", "alert( sid:1 # comment\n; )", true },
    { "alert( sid:1; /*id:0;*/ )", "alert( sid:1; /*id:0;*/ )", true },

    { nullptr, nullptr, false }
};

// __STRDUMP_DISABLE__
static const TestCase stub_tests[] =
{
#ifdef UNORDERED_OPTS
    { "alert( id:0; )", "alert( )", true },
    { "alert( sid:1; id:0; )", "alert( sid:1; )", true },
    { "alert( sid:1;id:0; )", "alert( sid:1;)", true },
    { "alert( id:0;sid:1; )", "alert( sid:1; )", true },

    { "alert( id:/*comment*/0; )", "alert( )", true },
    { "alert( id: #comment\n0; )", "alert( )", true },

    { R"_(alert( content:"foo"; ))_", "alert( )", true },
    { R"_(alert( content:"f;o"; ))_", "alert( )", true },
    { R"_(alert( content:"f\"o"; ))_", "alert( )", true },

    { R"_(alert( soid; rem:"soid"; /*soid*/ ))_",
      R"_(alert( soid; rem:"soid"; /*soid*/ ))_", true },

    { R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; flow:to_server,established; http_uri; content:"/j.php|3F|u|3D|", fast_pattern,nocase; content:"&v=f2&r=",depth 8,offset 41,nocase; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; service:http; reference:url,www.virustotal.com/file/bff436d8a2ccf1cdce56faabf341e97f59285435b5e73f952187bbfaf4df3396/analysis/; classtype:trojan-activity; sid:24062; rev:7; ))_", 
      R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; service:http; reference:url,www.virustotal.com/file/bff436d8a2ccf1cdce56faabf341e97f59285435b5e73f952187bbfaf4df3396/analysis/; classtype:trojan-activity; sid:24062; rev:7; ))_", 
      true },

#else
    { "alert( soid; id:0; )", "alert( soid; )", true },
    { "alert( sid:1; soid; id:0; )", "alert( sid:1; soid; )", true },
    { "alert( sid:1;soid;id:0; )", "alert( sid:1;soid;)", true },
    { "alert( soid;id:0;sid:1; )", "alert( soid;)", true },

    { "alert( soid; id:/*comment*/0; )", "alert( soid; )", true },
    { "alert( soid; id: #comment\n0; )", "alert( soid; )", true },

    { R"_(alert( soid; content:"foo"; ))_", "alert( soid; )", true },
    { R"_(alert( soid; content:"f;o"; ))_", "alert( soid; )", true },
    { R"_(alert( soid; content:"f\"o"; ))_", "alert( soid; )", true },

    { R"_(alert( rem:"soid"; /*soid*/ soid; ))_",
      R"_(alert( rem:"soid"; /*soid*/ soid; ))_", true },

    { R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; soid:a; flow:to_server,established; http_uri; content:"/j.php|3F|u|3D|", fast_pattern,nocase; content:"&v=f2&r=",depth 8,offset 41,nocase; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; service:http; reference:url,www.virustotal.com/file/bff436d8a2ccf1cdce56faabf341e97f59285435b5e73f952187bbfaf4df3396/analysis/; classtype:trojan-activity; sid:24062; rev:7; ))_", 
      R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; soid:a; ))_", 
      true },

#endif
    { nullptr, nullptr, false }
};

static const TestCase opts_tests[] =
{
#ifdef UNORDERED_OPTS
    { R"_(alert( soid; rem:"soid"; /*soid*/ ))_", R"_(alert( /*soid*/ ))_", true },

    { R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; flow:to_server,established; http_uri; content:"/j.php|3F|u|3D|", fast_pattern,nocase; content:"&v=f2&r=",depth 8,offset 41,nocase; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; service:http; reference:url,www.virustotal.com/file/bff436d8a2ccf1cdce56faabf341e97f59285435b5e73f952187bbfaf4df3396/analysis/; classtype:trojan-activity; sid:24062; rev:7; ))_", 
      R"_(flow:to_server,established; http_uri; content:"/j.php|3F|u|3D|", fast_pattern,nocase; content:"&v=f2&r=",depth 8,offset 41,nocase; )_", 
      true },

#else
    { R"_(alert( rem:"soid"; /*soid*/ soid; ))_", "", true },

    { R"_(alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Hufysk variant outbound connection"; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop; service:http; reference:url,www.virustotal.com/file/bff436d8a2ccf1cdce56faabf341e97f59285435b5e73f952187bbfaf4df3396/analysis/; classtype:trojan-activity; sid:24062; rev:7; soid:3_24062_7; flow:to_server,established; http_uri; content:"/j.php|3F|u|3D|", fast_pattern,nocase; content:"&v=f2&r=",depth 8,offset 41,nocase; ))_", 
      R"_(flow:to_server,established; http_uri; content:"/j.php|3F|u|3D|", fast_pattern,nocase; content:"&v=f2&r=",depth 8,offset 41,nocase; )_", 
      true },
#endif
    { nullptr, nullptr, false }
};
// __STRDUMP_ENABLE__

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

TEST_CASE("parse_so_rule", "[parser]")
{
    const TestCase* tc = syntax_tests;

    while ( tc->rule )
    {
        SoRuleParser sop(false);
        std::string stub;
        std::string opts;
        bool parse = sop.parse_so_rule(tc->rule, stub, opts);
        CHECK(parse == tc->result);
        CHECK(stub == tc->expect);
        ++tc;
    }
}

TEST_CASE("get_so_stub protected", "[parser]")
{
    const TestCase* tc = stub_tests;

    while ( tc->rule )
    {
        std::string stub;
        bool get = get_so_stub(tc->rule, false, stub);
        CHECK(get == tc->result);
        CHECK(stub == tc->expect);
        ++tc;
    }
}

TEST_CASE("get_so_options protected", "[parser]")
{
    const TestCase* tc = opts_tests;

    while ( tc->rule )
    {
        std::string opts;
        bool get = get_so_options(tc->rule, false, opts);
        CHECK(get == tc->result);
        CHECK(opts == tc->expect);
        ++tc;
    }
}

TEST_CASE("get_so_stub plain", "[parser]")
{
    const TestCase* tc = stub_tests;

    while ( tc->rule )
    {
        std::string stub;
        bool get = get_so_stub(tc->rule, true, stub);
        CHECK(get == tc->result);
        CHECK(stub == tc->rule);
        ++tc;
    }
}

TEST_CASE("get_so_options plain", "[parser]")
{
    const TestCase* tc = opts_tests;

    while ( tc->rule )
    {
        std::string opts;
        bool get = get_so_options(tc->rule, true, opts);
        CHECK(get == tc->result);
        CHECK(opts == "");
        ++tc;
    }
}
#endif

