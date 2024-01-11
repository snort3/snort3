//--------------------------------------------------------------------------
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
// js_test_options.cc author Danylo Kyrylov <dkyrylov@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_test_options.h"

#include <assert.h>

Config::Config(const Config& other) : type(other.type)
{
    switch (other.type)
    {
        case ReturnCode:
            val_jsret = other.val_jsret;
            break;
        case NormalizeIdentifiers:
        case NormalizeAsExternal:
        case CheckMixedEncoding:
        case CheckUnescapeNesting:
        case UseExpectedForLastPDU:
        case CheckOpenTag:
        case CheckClosingTag:
            val_bool = other.val_bool;
            break;
        case IgnoredIdsList:
        case IgnoredPropertiesList:
            val_string_set = other.val_string_set;
            break;
        case NormDepth:
        case IdentifierDepth:
        case MaxTemplateNesting:
        case MaxBracketDepth:
        case MaxScopeDepth:
        case MaxTokenBufSize:
        case ExpectedCursorPos:
            val_int = other.val_int;
            break;
        case TemporaryBuffer:
            val_string = other.val_string;
            break;
        default:
            assert(false);
    }
}

Config::~Config()
{
    // Explicitly destroy composite datatypes
    switch (type)
    {
        case IgnoredIdsList:
        case IgnoredPropertiesList:
            val_string_set.~unordered_set<std::string>();
            break;
        case TemporaryBuffer:
            val_string.~basic_string();
        default:
            break;
    }
}

void ConfigSet::set_overrides(const Overrides& values)
{
    for (const auto& conf : values)
    {
        switch (conf.type)
        {
            case ReturnCode:
                return_code = conf.val_jsret;
                break;
            case NormalizeIdentifiers:
                normalize_identifiers = conf.val_bool;
                break;
            case NormalizeAsExternal:
                normalize_as_external = conf.val_bool;
                break;
            case CheckMixedEncoding:
                check_mixed_encoding = conf.val_bool;
                break;
            case CheckUnescapeNesting:
                check_mixed_encoding = conf.val_bool;
                break;
            case UseExpectedForLastPDU:
                use_expected_for_last_pdu = conf.val_bool;
                break;
            case IgnoredIdsList:
                ignored_ids_list = conf.val_string_set;
                break;
            case IgnoredPropertiesList:
                ignored_properties_list = conf.val_string_set;
                break;
            case NormDepth:
                norm_depth = conf.val_int;
                break;
            case IdentifierDepth:
                identifier_depth = conf.val_int;
                break;
            case MaxTemplateNesting:
                max_template_nesting = conf.val_int;
                break;
            case MaxBracketDepth:
                max_bracket_depth = conf.val_int;
                break;
            case MaxScopeDepth:
                max_scope_depth = conf.val_int;
                break;
            case MaxTokenBufSize:
                max_token_buf_size = conf.val_int;
                break;
            case ExpectedCursorPos:
                expected_cursor_pos = conf.val_int;
                break;
            case CheckOpenTag:
                check_open_tag = conf.val_bool;
                break;
            case CheckClosingTag:
                check_closing_tag = conf.val_bool;
                break;
            case TemporaryBuffer:
                temporary_buffer = conf.val_string;
                break;
            default:
                assert(false);
        }
    }
}

Config return_code(JSTokenizer::JSRet val)
{ return {ConfigType::ReturnCode, val}; }

Config normalize_identifiers(bool val)
{ return {ConfigType::NormalizeIdentifiers, val}; }

Config normalize_as_external(bool val)
{ return {ConfigType::NormalizeAsExternal, val}; }

Config ignored_ids_list(StringSet val)
{ return {ConfigType::IgnoredIdsList, val}; }

Config ignored_properties_list(StringSet val)
{ return {ConfigType::IgnoredPropertiesList, val}; }

Config norm_depth(int val)
{ return {ConfigType::NormDepth, val}; }

Config identifier_depth(int val)
{ return {ConfigType::IdentifierDepth, val}; }

Config max_template_nesting(int val)
{ return {ConfigType::MaxTemplateNesting, val}; }

Config max_bracket_depth(int val)
{ return {ConfigType::MaxBracketDepth, val}; }

Config max_scope_depth(int val)
{ return {ConfigType::MaxScopeDepth, val}; }

Config max_token_buf_size(int val)
{ return {ConfigType::MaxTokenBufSize, val}; }

Config check_mixed_encoding(bool val)
{ return {ConfigType::CheckMixedEncoding, val}; }

Config check_unescape_nesting(bool val)
{ return {ConfigType::CheckUnescapeNesting, val}; }

Config use_expected_for_last_pdu(bool val)
{ return {ConfigType::UseExpectedForLastPDU, val}; }

Config expected_cursor_pos(int val)
{ return {ConfigType::ExpectedCursorPos, val}; }

Config check_open_tag(bool val)
{ return {ConfigType::CheckOpenTag, val}; }

Config check_closing_tag(bool val)
{ return {ConfigType::CheckClosingTag, val}; }

Config temporary_buffer(std::string val)
{ return {ConfigType::TemporaryBuffer, val}; }

