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

#include "nhttp_field.h"
#include "nhttp_infractions.h"
#include "nhttp_event_gen.h"
#include "nhttp_normalizers.h"

class UriNormalizer
{
public:
    static void normalize(const Field& input, Field& result, bool do_path, uint8_t* buffer,
        NHttpInfractions& infractions, NHttpEventGen& events);
    static bool need_norm_path(const Field& uri_component);
    static bool need_norm_no_path(const Field& uri_component);
    static const unsigned URI_NORM_EXPANSION = 1;

private:
    static const NHttpEnums::CharAction uri_char[256];
    static const bool good_percent[256];

    static NormFunc norm_char_clean;
    static void norm_backslash(uint8_t* buf, int32_t length, NHttpInfractions& infractions,
        NHttpEventGen& events);
    static int32_t norm_path_clean(uint8_t* buf, const int32_t in_length,
        NHttpInfractions& infractions, NHttpEventGen& events);
};

#endif

