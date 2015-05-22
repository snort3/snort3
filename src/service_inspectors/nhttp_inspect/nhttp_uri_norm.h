//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "nhttp_scratch_pad.h"
#include "nhttp_field.h"
#include "nhttp_infractions.h"

class UriNormalizer
{
public:
    static void normalize(const Field& input, Field& result, bool do_path, ScratchPad& scratch_pad,
        NHttpInfractions& infractions);

private:
    static const NHttpEnums::CharAction uri_char[256];
    static const bool good_percent[256];

    static bool no_path_check(const uint8_t* in_buf, int32_t in_length,
        NHttpInfractions& infractions);
    static bool path_check(const uint8_t* in_buf, int32_t in_length,
        NHttpInfractions& infractions);

    static int32_t norm_char_clean(const uint8_t*, int32_t, uint8_t*, NHttpInfractions&,
        const void* not_used);
    static int32_t norm_backslash(const uint8_t*, int32_t, uint8_t*, NHttpInfractions&,
        const void* not_used);
    static int32_t norm_path_clean(const uint8_t*, int32_t, uint8_t*, NHttpInfractions&,
        const void* not_used);
};

#endif

