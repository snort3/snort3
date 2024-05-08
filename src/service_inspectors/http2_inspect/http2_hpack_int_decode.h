//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_hpack_int_decode.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_HPACK_INT_DECODE_H
#define HTTP2_HPACK_INT_DECODE_H

#include "http2_enum.h"
#include "http2_varlen_int_decode.h"

#include "helpers/event_gen.h"
#include "helpers/infractions.h"
#include "main/snort_types.h"

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;

using Http2EventGen = EventGen<Http2Enums::EVENT__MAX_VALUE, Http2Enums::EVENT__NONE,
    Http2Enums::HTTP2_GID>;

using Http2HpackIntDecode = VarLengthIntDecode<Http2EventGen, Http2Infractions>;

#endif

