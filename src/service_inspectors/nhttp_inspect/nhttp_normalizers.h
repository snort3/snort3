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
// nhttp_normalizers.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_NORMALIZERS_H
#define NHTTP_NORMALIZERS_H

#include "nhttp_infractions.h"
#include "nhttp_event_gen.h"
#include "nhttp_field.h"
#include "nhttp_str_to_code.h"

// There are currently no normalization functions that make header values bigger. Changes are
// required to HeaderNormalizer::normalize() to allocate more space before you can introduce a
// normalizer that may expand a header value.
//
// Normalization functions must return an output buffer with nonnegative length. Status codes are
// not acceptable.
typedef int32_t (NormFunc)(const uint8_t*, int32_t, uint8_t*, NHttpInfractions&, NHttpEventGen&);
NormFunc norm_to_lower;
NormFunc norm_remove_lws;

// Other normalization-related utilities
int64_t norm_decimal_integer(const Field& input);
int32_t norm_last_token_code(const Field& input, const StrCode table[]);
bool chunked_before_end(const Field& input);

#endif

