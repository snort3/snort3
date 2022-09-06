//--------------------------------------------------------------------------
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
// js_test_options.h author Danylo Kyrylov <dkyrylov@cisco.com>

#ifndef JS_TEST_OPTIONS_H
#define JS_TEST_OPTIONS_H

#include <list>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "utils/js_identifier_ctx.h"
#include "utils/js_normalizer.h"

typedef std::unordered_set<std::string> StringSet;

enum ConfigType
{
    ReturnCode,
    NormalizeIdentifiers,
    NormalizeAsExternal,
    IgnoredIdsList,
    IgnoredPropertiesList,
    NormDepth,
    IdentifierDepth,
    MaxTemplateNesting,
    MaxBracketDepth,
    MaxScopeDepth,
    MaxTokenBufSize,
    CheckMixedEncoding,
    CheckUnescapeNesting,
    UseExpectedForLastPDU,
    ExpectedCursorPos,
    CheckOpenTag,
    CheckClosingTag,
    TemporaryBuffer
};

struct Config
{
    ConfigType type;
    union
    {
        JSTokenizer::JSRet val_jsret;
        bool val_bool;
        int val_int;
        StringSet val_string_set;
        std::string val_string;
    };

    Config(const Config& other);
    Config(ConfigType type, JSTokenizer::JSRet val) : type(type), val_jsret(val){}
    Config(ConfigType type, bool val) : type(type), val_bool(val){}
    Config(ConfigType type, int val) : type(type), val_int(val){}
    Config(ConfigType type, const StringSet& val) : type(type), val_string_set(val){}
    Config(ConfigType type, const std::string& val) : type(type), val_string(val){}
    ~Config();
};

typedef std::initializer_list<Config> Overrides;

class ConfigSet
{
protected:
    template<class T>
    class Field
    {
        T val;
        bool set = false;

    public:
        Field()
        { }
        Field(const T& val): val(val)
        { }
        operator const T&() const
        { return val; }
        T& operator =(const T& new_value)
        { val = new_value; set = true; return val; }
        bool is_set() const
        { return set; }
        void unset()
        { set = false; }
    };

public:
    Field<JSTokenizer::JSRet> return_code;
    Field<bool> normalize_identifiers;
    Field<bool> normalize_as_external;
    Field<StringSet> ignored_ids_list;
    Field<StringSet> ignored_properties_list;
    Field<int> norm_depth;
    Field<int> identifier_depth;
    Field<int> max_template_nesting;
    Field<int> max_bracket_depth;
    Field<int> max_scope_depth;
    Field<int> max_token_buf_size;
    Field<bool> check_mixed_encoding;
    Field<bool> check_unescape_nesting;

    // If true, check only new normalized part, otherwise check the whole normalized script
    Field<bool> use_expected_for_last_pdu;
    Field<int> expected_cursor_pos;
    Field<bool> check_open_tag;
    Field<bool> check_closing_tag;

    // Add check for contents of the temporary buffer
    Field<std::string> temporary_buffer;

protected:
    void set_overrides(const Overrides& overrides);
};

Config return_code(JSTokenizer::JSRet val);
Config normalize_identifiers(bool val);
Config normalize_as_external(bool val);
Config ignored_ids_list(StringSet val);
Config ignored_properties_list(StringSet val);
Config norm_depth(int val);
Config identifier_depth(int val);
Config max_template_nesting(int val);
Config max_bracket_depth(int val);
Config max_scope_depth(int val);
Config max_token_buf_size(int val);
Config check_mixed_encoding(bool val);
Config check_unescape_nesting(bool val);

// If true, check only new normalized part, otherwise check the whole normalized script
Config use_expected_for_last_pdu(bool val);
Config expected_cursor_pos(int val);
Config check_open_tag(bool val);
Config check_closing_tag(bool val);

// Add check for contents of the temporary buffer
Config temporary_buffer(std::string val);

#endif

