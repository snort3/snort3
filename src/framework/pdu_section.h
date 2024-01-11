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
// pdu_section.h author Maya Dagon <mdagon@cisco.com>

#ifndef PDU_SECTION_H
#define PDU_SECTION_H

// PDU section in which an IPS option provides the buffer.
// The sections are ordered from earliest to latest.
// The latest section is used to determine the rule group.
// Currently only used by ips options that apply to HTTP. The rest default to PS_NONE.

#include "main/snort_types.h"

namespace snort
{
// PS_HEADER_BODY is used for rule options that can work on both header and body.
// It was added to make the rule timing selection easier:
// - if combined with header the rule should still be evaluated in both header and body.
// - if combined with body or trailer should be evaluated at body/trailer.
// PS_ERROR is used for invalid combination of sections:
// trailer and body sections can be combined only if it's a request trailer in a to_client direction
// When updating this enum, also update section_to_str
enum PduSection { PS_NONE = 0, PS_HEADER, PS_HEADER_BODY, PS_BODY, PS_TRAILER, PS_MAX = PS_TRAILER,
    PS_ERROR };

// Bitmask with all of supported sections
using section_flags = uint16_t;

inline section_flags section_to_flag(PduSection sect)
{ return 1<<sect; }
}

#endif
