//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_uri_norm.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_URI_NORM_H
#define NHTTP_URI_NORM_H

#include <vector>
#include <string>

#include "nhttp_enum.h"
#include "nhttp_field.h"
#include "nhttp_module.h"
#include "nhttp_infractions.h"
#include "nhttp_event_gen.h"

class UriNormalizer
{
public:
    static const unsigned URI_NORM_EXPANSION = 1;

    static bool need_norm(const Field& uri_component, bool do_path,
        const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions,
        NHttpEventGen& events);
    static void normalize(const Field& input, Field& result, bool do_path, uint8_t* buffer,
        const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions,
        NHttpEventGen& events);
    static bool classic_need_norm(const Field& uri_component, bool do_path,
        const NHttpParaList::UriParam& uri_param);
    static void classic_normalize(const Field& input, Field& result, uint8_t* buffer,
        const NHttpParaList::UriParam& uri_param);
    static void load_default_unicode_map(uint8_t map[65536]);
    static void load_unicode_map(uint8_t map[65536], const char* filename, int code_page);

private:
    static bool need_norm_path(const Field& uri_component,
        const NHttpParaList::UriParam& uri_param);
    static bool need_norm_no_path(const Field& uri_component,
        const NHttpParaList::UriParam& uri_param);
    static int32_t norm_char_clean(const Field& input, uint8_t* out_buf,
        const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions,
        NHttpEventGen& events);
    static int32_t norm_percent_processing(const Field& input, uint8_t* out_buf,
        const NHttpParaList::UriParam& uri_param, bool& utf8_needed,
        std::vector<bool>& percent_encoded, bool& double_decoding_needed,
        NHttpInfractions& infractions, NHttpEventGen& events);
    static int32_t norm_utf8_processing(const Field& input, uint8_t* out_buf,
        const NHttpParaList::UriParam& uri_param, const std::vector<bool>& percent_encoded,
        bool& double_decoding_needed, NHttpInfractions& infractions, NHttpEventGen& events);
    static int32_t norm_double_decode(const Field& input, uint8_t* out_buf,
        const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions,
        NHttpEventGen& events);
    static void norm_substitute(uint8_t* buf, int32_t length,
        const NHttpParaList::UriParam& uri_param,  NHttpInfractions& infractions,
        NHttpEventGen& events);
    static int32_t norm_path_clean(uint8_t* buf, const int32_t in_length,
        NHttpInfractions& infractions, NHttpEventGen& events);
    static void detect_bad_char(const Field& uri_component,
        const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions,
        NHttpEventGen& events);
    static uint8_t reduce_to_eight_bits(uint16_t value, const NHttpParaList::UriParam& uri_param,
        NHttpInfractions& infractions, NHttpEventGen& events);
    static bool advance_to_code_page(FILE* file, int page_to_use);
    static bool map_code_points(FILE* file, uint8_t* map);

    static inline bool is_percent_encoding(const Field& input, int32_t index);
    static inline uint8_t extract_percent_encoding(const Field& input, int32_t index);
    static inline bool is_u_encoding(const Field& input, int32_t index);
    static inline uint16_t extract_u_encoding(const Field& input, int32_t index);

    // An artifice used by the classic normalization methods to disable event generation
    class NHttpDummyEventGen : public NHttpEventGen
    {
        void create_event(NHttpEnums::EventSid) override {}
    };
};

bool UriNormalizer::is_percent_encoding(const Field& input, int32_t index)
{
    return (index+2 < input.length) &&
           (NHttpEnums::as_hex[input.start[index+1]] != -1) &&
           (NHttpEnums::as_hex[input.start[index+2]] != -1);
}

uint8_t UriNormalizer::extract_percent_encoding(const Field& input, int32_t index)
{
    return NHttpEnums::as_hex[input.start[index+1]] << 4 |
           NHttpEnums::as_hex[input.start[index+2]];
}

bool UriNormalizer::is_u_encoding(const Field& input, int32_t index)
{
    return (index+5 < input.length) &&
           ((input.start[index+1] == 'u') || (input.start[index+1] == 'U')) &&
           (NHttpEnums::as_hex[input.start[index+2]] != -1) &&
           (NHttpEnums::as_hex[input.start[index+3]] != -1) &&
           (NHttpEnums::as_hex[input.start[index+4]] != -1) &&
           (NHttpEnums::as_hex[input.start[index+5]] != -1);
}

uint16_t UriNormalizer::extract_u_encoding(const Field& input, int32_t index)
{
    return (NHttpEnums::as_hex[input.start[index+2]] << 12) |
           (NHttpEnums::as_hex[input.start[index+3]] << 8)  |
           (NHttpEnums::as_hex[input.start[index+4]] << 4)  |
            NHttpEnums::as_hex[input.start[index+5]];
}

#endif

