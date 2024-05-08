//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// js_enum.h authors Danylo Kyrylov <dkyrylov@cisco.com>, Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef JS_ENUM_H
#define JS_ENUM_H

#include "helpers/event_gen.h"

namespace jsn
{

static constexpr unsigned js_gid = 154;

enum
{
    TRACE_PROC = 0,
    TRACE_DUMP,
    TRACE_PDF_PROC,
    TRACE_PDF_DUMP
};

// This enum must be synchronized with JSNormModule::peg_names[] in js_norm_module.cc
enum PEG_COUNT
{
    PEG_BYTES = 0,
    PEG_IDENTIFIERS,
    PEG_IDENTIFIER_OVERFLOWS,
    PEG_COUNT_MAX
};

// This enum must be synchronized with JSNormModule::events[] in js_norm_module.cc
enum EventSid
{
    EVENT__NONE = -1,
    EVENT_NEST_UNESCAPE_FUNC = 1,
    EVENT_MIXED_UNESCAPE_SEQUENCE = 2,
    EVENT_BAD_TOKEN = 3,
    EVENT_OPENING_TAG = 4,
    EVENT_CLOSING_TAG = 5,
    EVENT_IDENTIFIER_OVERFLOW = 6,
    EVENT_BRACKET_NEST_OVERFLOW = 7,
    EVENT_DATA_LOST = 8,
    EVENT_SCOPE_NEST_OVERFLOW = 9,
    EVENT__MAX_VALUE
};

}

using JSEvents = EventGen<jsn::EVENT__MAX_VALUE, jsn::EVENT__NONE, jsn::js_gid>;

#endif
