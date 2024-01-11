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
// http2_hpack_string_decode.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_HPACK_STRING_DECODE_H
#define HTTP2_HPACK_STRING_DECODE_H

#include "http2_hpack_int_decode.h"
#include "http2_varlen_string_decode.h"

using Http2HpackStringDecode = VarLengthStringDecode<Http2HpackIntDecode, Http2EventGen, Http2Infractions>;

#endif

