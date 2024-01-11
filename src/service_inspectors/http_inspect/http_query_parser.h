//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_query_parser.h author Brandon Stultz <brastult@cisco.com>

#ifndef HTTP_QUERY_PARSER_H
#define HTTP_QUERY_PARSER_H

#include <string>
#include <unordered_map>
#include <vector>

#include "http_common.h"
#include "http_field.h"
#include "http_flow_data.h"
#include "http_module.h"
#include "http_param.h"

struct KeyValue
{
    Field key;
    Field value;
};

typedef std::vector<KeyValue*> KeyValueVec;

class ParameterData
{
public:
    ParameterData() = default;

    ~ParameterData()
    {
        for ( KeyValue* kv : kv_vec )
            delete kv;
    }

public:
    KeyValueVec kv_vec;
    bool parsed = false;
};

typedef std::unordered_map<std::string, ParameterData> ParameterMap;

class HttpQueryParser
{
public:
    HttpQueryParser(const uint8_t* buffer_, unsigned buffer_len_,
        const uint8_t* norm_buffer_, unsigned norm_buffer_len_,
        const HttpParaList::UriParam& uri_config_,
        HttpFlowData* session_data_,
        HttpCommon::SourceId source_id_)
        : buffer(buffer_), buffer_len(buffer_len_),
          norm_buffer(norm_buffer_), norm_buffer_len(norm_buffer_len_),
          uri_config(uri_config_), session_data(session_data_),
          source_id(source_id_) {}

    void parse(const HttpParam& param, ParameterData& data);

    struct Parameter
    {
        const uint8_t* key;
        const uint8_t* value;
        unsigned key_len;
        unsigned value_len;
    };

private:
    void create_event(int sid);

    void unescape(const Field& raw, Field& norm);

    bool parse_parameter(Parameter& p);
    bool parse_key(Parameter& p);
    bool parse_value(Parameter& p);

    const uint8_t* buffer;
    unsigned buffer_len;

    const uint8_t* norm_buffer;
    unsigned norm_buffer_len;

    unsigned index = 0;

    static const unsigned MAX_REPEAT_PARAMS = 100;

    const HttpParaList::UriParam& uri_config;
    HttpFlowData* const session_data;
    const HttpCommon::SourceId source_id;
};

#endif

