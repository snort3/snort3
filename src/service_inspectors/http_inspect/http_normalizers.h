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
// http_normalizers.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_NORMALIZERS_H
#define HTTP_NORMALIZERS_H

#include "http_infractions.h"
#include "http_event_gen.h"
#include "http_field.h"
#include "http_str_to_code.h"

// There are currently no normalization functions that make header values bigger. Changes are
// required to HeaderNormalizer::normalize() to allocate more space before you can introduce a
// normalizer that may expand a header value.
//
// Normalization functions must return an output buffer with nonnegative length. Status codes are
// not acceptable.
typedef int32_t (NormFunc)(const uint8_t*, int32_t, uint8_t*, HttpInfractions*, HttpEventGen*);
NormFunc norm_to_lower;
NormFunc norm_remove_lws;
NormFunc norm_remove_quotes_lws;

// Other normalization-related utilities
void get_last_token(const Field& input, Field& last_token, char ichar);
int64_t norm_decimal_integer(const Field& input);

#endif

