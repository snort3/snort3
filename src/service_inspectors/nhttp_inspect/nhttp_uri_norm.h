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
        std::vector<bool>& percent_encoded, NHttpInfractions& infractions, NHttpEventGen& events);
    static int32_t norm_utf8_processing(const Field& input, uint8_t* out_buf,
        const NHttpParaList::UriParam& uri_param, const std::vector<bool>& percent_encoded,
        NHttpInfractions& infractions, NHttpEventGen& events);
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

    // An artifice used by the classic normalization methods to disable event generation
    class NHttpDummyEventGen : public NHttpEventGen
    {
        void create_event(NHttpEnums::EventSid) override {}
    };
};

#endif

