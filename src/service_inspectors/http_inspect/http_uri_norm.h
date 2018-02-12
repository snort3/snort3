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
// http_uri_norm.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_URI_NORM_H
#define HTTP_URI_NORM_H

#include <vector>
#include <string>

#include "http_enum.h"
#include "http_field.h"
#include "http_module.h"
#include "http_infractions.h"
#include "http_event_gen.h"

class UriNormalizer
{
public:
    static const unsigned URI_NORM_EXPANSION = 1;

    static bool need_norm(const Field& uri_component, bool do_path,
        const HttpParaList::UriParam& uri_param, HttpInfractions* infractions,
        HttpEventGen* events);
    static void normalize(const Field& input, Field& result, bool do_path, uint8_t* buffer,
        const HttpParaList::UriParam& uri_param, HttpInfractions* infractions,
        HttpEventGen* events);
    static bool classic_need_norm(const Field& uri_component, bool do_path,
        const HttpParaList::UriParam& uri_param);
    static void classic_normalize(const Field& input, Field& result,
        const HttpParaList::UriParam& uri_param);
    static void load_default_unicode_map(uint8_t map[65536]);
    static void load_unicode_map(uint8_t map[65536], const char* filename, int code_page);

private:
    static bool need_norm_path(const Field& uri_component,
        const HttpParaList::UriParam& uri_param);
    static bool need_norm_no_path(const Field& uri_component,
        const HttpParaList::UriParam& uri_param);
    static int32_t norm_char_clean(const Field& input, uint8_t* out_buf,
        const HttpParaList::UriParam& uri_param, HttpInfractions* infractions,
        HttpEventGen* events);
    static int32_t norm_percent_processing(const Field& input, uint8_t* out_buf,
        const HttpParaList::UriParam& uri_param, bool& utf8_needed,
        std::vector<bool>& percent_encoded, bool& double_decoding_needed,
        HttpInfractions* infractions, HttpEventGen* events);
    static int32_t norm_utf8_processing(const Field& input, uint8_t* out_buf,
        const HttpParaList::UriParam& uri_param, const std::vector<bool>& percent_encoded,
        bool& double_decoding_needed, HttpInfractions* infractions, HttpEventGen* events);
    static int32_t norm_double_decode(const Field& input, uint8_t* out_buf,
        const HttpParaList::UriParam& uri_param, HttpInfractions* infractions,
        HttpEventGen* events);
    static void norm_substitute(uint8_t* buf, int32_t length,
        const HttpParaList::UriParam& uri_param,  HttpInfractions* infractions,
        HttpEventGen* events);
    static int32_t norm_path_clean(uint8_t* buf, const int32_t in_length,
        HttpInfractions* infractions, HttpEventGen* events);
    static void detect_bad_char(const Field& uri_component,
        const HttpParaList::UriParam& uri_param, HttpInfractions* infractions,
        HttpEventGen* events);
    static uint8_t reduce_to_eight_bits(uint16_t value, const HttpParaList::UriParam& uri_param,
        HttpInfractions* infractions, HttpEventGen* events);
    static bool advance_to_code_page(FILE* file, int page_to_use);
    static bool map_code_points(FILE* file, uint8_t* map);

    static inline bool is_percent_encoding(const Field& input, int32_t index);
    static inline uint8_t extract_percent_encoding(const Field& input, int32_t index);
    static inline bool is_u_encoding(const Field& input, int32_t index);
    static inline uint16_t extract_u_encoding(const Field& input, int32_t index);

    // An artifice used by the classic normalization methods to disable event generation
    class HttpDummyEventGen : public HttpEventGen
    {
        void create_event(int) override {}
    };
};

bool UriNormalizer::is_percent_encoding(const Field& input, int32_t index)
{
    return (index+2 < input.length()) &&
           (HttpEnums::as_hex[input.start()[index+1]] != -1) &&
           (HttpEnums::as_hex[input.start()[index+2]] != -1);
}

uint8_t UriNormalizer::extract_percent_encoding(const Field& input, int32_t index)
{
    return HttpEnums::as_hex[input.start()[index+1]] << 4 |
           HttpEnums::as_hex[input.start()[index+2]];
}

bool UriNormalizer::is_u_encoding(const Field& input, int32_t index)
{
    return (index+5 < input.length()) &&
           ((input.start()[index+1] == 'u') || (input.start()[index+1] == 'U')) &&
           (HttpEnums::as_hex[input.start()[index+2]] != -1) &&
           (HttpEnums::as_hex[input.start()[index+3]] != -1) &&
           (HttpEnums::as_hex[input.start()[index+4]] != -1) &&
           (HttpEnums::as_hex[input.start()[index+5]] != -1);
}

uint16_t UriNormalizer::extract_u_encoding(const Field& input, int32_t index)
{
    return (HttpEnums::as_hex[input.start()[index+2]] << 12) |
           (HttpEnums::as_hex[input.start()[index+3]] << 8)  |
           (HttpEnums::as_hex[input.start()[index+4]] << 4)  |
            HttpEnums::as_hex[input.start()[index+5]];
}

#endif

