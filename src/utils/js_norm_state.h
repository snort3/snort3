//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
// js_norm_state.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef JS_NORM_STATE_H
#define JS_NORM_STATE_H

#include "main/snort_types.h"

namespace snort
{
#define ALERT_UNEXPECTED_TAG 0x1

struct JSNormState
{
    int64_t norm_depth;
    uint16_t alerts;
};
}

#endif // JS_NORM_STATE_H

