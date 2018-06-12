//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// base64_encoder.h author Russ Combs <rucombs@cisco.com>

#ifndef BASE64_ENCODER_H
#define BASE64_ENCODER_H

// this is based on the excellent work by devolve found at
// https://sourceforge.net/projects/libb64/.

// usage: instantiate, encode+, finish
// buf must hold 2*length_in

#include <cstdint>
#include "main/snort_types.h"

namespace snort
{
class SO_PUBLIC Base64Encoder
{
public:
    Base64Encoder()
    { reset(); }

    unsigned encode(const uint8_t* plain_text, unsigned length, char* buf);
    unsigned finish(char* buf);

    void reset()
    { step = step_A; state = 0; }

private:
    enum Steps { step_A, step_B, step_C };
    Steps step;
    uint8_t state;
};
}
#endif

