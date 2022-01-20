//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// http_query_parser.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "http_enum.h"
#include "http_query_parser.h"
#include "http_uri_norm.h"

using namespace HttpEnums;

void HttpQueryParser::create_event(int sid)
{
    session_data->events[source_id]->create_event(sid);
}

void HttpQueryParser::unescape(const Field& raw, Field& norm)
{
    if ( raw.length() > 0 )
    {
        if ( UriNormalizer::classic_need_norm(raw, false, uri_config) )
        {
            UriNormalizer::classic_normalize(raw, norm, false, uri_config);
            return;
        }
    }

    norm.set(raw);
}

void HttpQueryParser::parse(const HttpParam& param, ParameterData& data)
{
    // check if parameter is present in normalized buffer
    if( param.search_nocase(norm_buffer, norm_buffer_len) < 0 )
        return;

    const std::string& key = param.str_upper();

    unsigned kv_index = 0;
    index = 0;

    while ( index < buffer_len )
    {
        if ( kv_index >= MAX_REPEAT_PARAMS )
        {
            HttpModule::increment_peg_counts(PEG_EXCESS_PARAMS);
            create_event(EVENT_EXCESS_REPEAT_PARAMS);
            return;
        }

        Parameter p = {};

        if ( !parse_parameter(p) )
            return;

        if ( p.key_len == 0 )
            continue;

        Field raw_key(p.key_len, p.key);
        Field raw_value(p.value_len, p.value);

        KeyValue* fields = new KeyValue;

        Field& norm_key = fields->key;
        Field& norm_value = fields->value;

        // normalize the key
        unescape(raw_key, norm_key);

        if ( (unsigned)norm_key.length() != key.length() )
        {
            delete fields;
            continue;
        }

        const char* norm_key_str = (const char*)norm_key.start();

        if ( strncasecmp(norm_key_str, key.c_str(), key.length()) )
        {
            delete fields;
            continue;
        }

        // normalize the value
        unescape(raw_value, norm_value);

        // cache the parameter
        data.kv_vec.push_back(fields);
        HttpModule::increment_peg_counts(PEG_PARAMS);
        kv_index++;
    }
}

bool HttpQueryParser::parse_parameter(Parameter& p)
{
    if ( !parse_key(p) )
        return false;

    if ( !parse_value(p) )
        return false;

    return true;
}

bool HttpQueryParser::parse_key(Parameter& p)
{
    const uint8_t* term;

    if ( index >= buffer_len )
        return false;

    p.key = buffer + index;

    unsigned remaining = buffer_len - index;

    // locate delimiter
    term = (const uint8_t*)memchr(p.key, '=', remaining);

    if ( !term )
        return false;

    p.key_len = term - p.key;

    index += p.key_len + 1;

    return true;
}

bool HttpQueryParser::parse_value(Parameter& p)
{
    const uint8_t* amp;
    const uint8_t* semi;
    const uint8_t* term;

    if ( index >= buffer_len )
        return false;

    p.value = buffer + index;

    unsigned remaining = buffer_len - index;

    // locate delimiter
    amp = (const uint8_t*)memchr(p.value, '&', remaining);
    semi = (const uint8_t*)memchr(p.value, ';', remaining);

    if ( amp && !semi )
        term = amp;
    else if ( !amp && semi )
        term = semi;
    else
        term = (amp < semi) ? amp : semi;

    if ( !term )
    {
        // last parameter
        p.value_len = remaining;
        index += remaining;
        return true;
    }

    p.value_len = term - p.value;

    index += p.value_len + 1;

    return true;
}

