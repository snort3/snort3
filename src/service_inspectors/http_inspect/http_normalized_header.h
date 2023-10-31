//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_normalized_header.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_NORMALIZED_HEADER_H
#define HTTP_NORMALIZED_HEADER_H

#include "http_event.h"
#include "http_field.h"

class HttpMsgHeadShared;

//-------------------------------------------------------------------------
// NormalizedHeader class
//-------------------------------------------------------------------------

class NormalizedHeader
{
public:
    NormalizedHeader(NormalizedHeader* next_, int32_t count_, HttpEnums::HeaderId id_) :
        next(next_), count(count_), id(id_) {}
    const Field& get_norm(HttpInfractions* infractions, HttpEventGen* events,
        const HttpEnums::HeaderId header_name_id[], const Field header_value[],
        const int32_t num_headers);
    const Field& get_comma_separated_raw(const HttpMsgHeadShared& msg_head, HttpInfractions* infractions,
	HttpEventGen* events, const HttpEnums::HeaderId header_name_id[], const Field header_value[],
        const int32_t num_headers);

    NormalizedHeader* next;
    int32_t count;
    const HttpEnums::HeaderId id;

private:
    // Header normalization strategies. There should be one defined for every different way we can
    // process a header field value.
    class HeaderNormalizer;
    static const HeaderNormalizer NORMALIZER_BASIC;
    static const HeaderNormalizer NORMALIZER_HOST;
    static const HeaderNormalizer NORMALIZER_CASE_INSENSITIVE;
    static const HeaderNormalizer NORMALIZER_NUMBER;
    static const HeaderNormalizer NORMALIZER_TOKEN_LIST;
    static const HeaderNormalizer NORMALIZER_METHOD_LIST;
    static const HeaderNormalizer NORMALIZER_DATE;
    static const HeaderNormalizer NORMALIZER_URI;
    static const HeaderNormalizer NORMALIZER_CONTENT_LENGTH;
    static const HeaderNormalizer NORMALIZER_CHARSET;

    // Master table of known header fields and their normalization strategies.
    static const HeaderNormalizer* const header_norms[];

    Field norm;
    Field comma_separated_raw;
};

#endif

