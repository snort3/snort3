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
// http_param.h author Brandon Stultz <brastult@cisco.com>

#ifndef HTTP_PARAM_H
#define HTTP_PARAM_H

#include <algorithm>
#include <cassert>
#include <string>

#include "helpers/literal_search.h"

class HttpParam
{
public:
    HttpParam(const std::string& param_, bool nocase_)
        : param(param_), param_upper(param_), nocase(nocase_)
    {
        assert(param.length() > 0);

        std::transform(param_upper.begin(), param_upper.end(),
            param_upper.begin(), ::toupper);

        const uint8_t* pattern = (const uint8_t*)param_upper.c_str();
        unsigned pattern_length = param_upper.length();

        search_handle = snort::LiteralSearch::setup();

        searcher = snort::LiteralSearch::instantiate(
            search_handle, pattern, pattern_length, true
        );
    }

    ~HttpParam()
    {
        delete searcher;
        snort::LiteralSearch::cleanup(search_handle);
    }

    bool operator==(const HttpParam& rhs) const
    { return param == rhs.param && nocase == rhs.nocase; }

    const std::string& str() const
    { return param; }

    const std::string& str_upper() const
    { return param_upper; }

    const char* c_str() const
    { return param.c_str(); }

    unsigned length() const
    { return param.length(); }

    bool is_nocase() const
    { return nocase; }

    int search_nocase(const uint8_t* buffer, unsigned buffer_len) const
    {
        assert(searcher);
        return searcher->search(search_handle, buffer, buffer_len);
    }

private:
    std::string param;
    std::string param_upper;
    bool nocase = false;
    snort::LiteralSearch* searcher = nullptr;
    snort::LiteralSearch::Handle* search_handle = nullptr;
};

#endif

