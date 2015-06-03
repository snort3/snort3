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
// nhttp_head_norm.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_HEAD_NORM_H
#define NHTTP_HEAD_NORM_H

#include "nhttp_scratch_pad.h"
#include "nhttp_field.h"
#include "nhttp_infractions.h"
#include "nhttp_normalizers.h"

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
    constexpr HeaderNormalizer(
        NHttpEnums::NormFormat _format, bool _concatenate_repeats,
        NormFunc* f1, const void* f1_arg,
        NormFunc* f2, const void* f2_arg,
        NormFunc* f3, const void* f3_arg) :
        format(_format),
        concatenate_repeats(_concatenate_repeats),
        normalizer { f1, f2, f3 },
        norm_arg { f1_arg, f2_arg, f3_arg },
        num_normalizers((f1 != nullptr) + (f1 != nullptr)*(f2 != nullptr) + (f1 != nullptr)*(f2 !=
            nullptr)*(f3 != nullptr)) { }

    void normalize(const NHttpEnums::HeaderId head_id, const int count, ScratchPad& scratch_pad,
        NHttpInfractions& infractions, NHttpEventGen& events,
        const NHttpEnums::HeaderId header_name_id[], const Field header_value[],
        const int32_t num_headers, Field& result_field) const;
    NHttpEnums::NormFormat get_format() const { return format; }

private:
    static int32_t derive_header_content(const uint8_t* value, int32_t length, uint8_t* buffer);

    const NHttpEnums::NormFormat format;
    const bool concatenate_repeats;
    NormFunc* const normalizer[3];
    const void* const norm_arg[3];
    const int num_normalizers;
};

#endif

