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
// http_header_normalizer.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_HEADER_NORMALIZER_H
#define HTTP_HEADER_NORMALIZER_H

#include "http_field.h"
#include "http_infractions.h"
#include "http_normalizers.h"

//-------------------------------------------------------------------------
// HeaderNormalizer class
// Strategies for normalizing HTTP header field values
//-------------------------------------------------------------------------

// Three normalization functions per HeaderNormalizer seems likely to be enough. Nothing subtle
// will break if you choose to expand it to four or more. Just a whole bunch of signatures and
// initializers to update. When defining a HeaderNormalizer don't leave holes in the normalizer
// list. E.g. if you have two normalizers they must be first and second. If you do first and third
// instead it won't explode but the third one won't be used either.

class HeaderNormalizer
{
public:
    constexpr HeaderNormalizer(HttpEnums::EventSid _repeat_event,
        HttpEnums::Infraction _repeat_inf, bool _alert_ws,
        NormFunc* f1, NormFunc* f2, NormFunc* f3)
        : repeat_event(_repeat_event), repeat_inf(_repeat_inf), alert_ws(_alert_ws),
        normalizer { f1, f2, f3 },
        num_normalizers((f1 != nullptr) + (f1 != nullptr)*(f2 != nullptr) + (f1 != nullptr)*(f2 !=
            nullptr)*(f3 != nullptr)) { }

    void normalize(const HttpEnums::HeaderId head_id, const int count,
        HttpInfractions* infractions, HttpEventGen* events,
        const HttpEnums::HeaderId header_name_id[], const Field header_value[],
        const int32_t num_headers, Field& result_field) const;

private:
    const HttpEnums::EventSid repeat_event;
    const HttpEnums::Infraction repeat_inf;
    const bool alert_ws;  // alert if white space in middle of value
    NormFunc* const normalizer[3];
    const int num_normalizers;
};

#endif

