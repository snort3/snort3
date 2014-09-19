/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// ipv6_util.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef IPV6_UTIL_H
#define IPV6_UTIL_H

#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "protocols/packet.h"
#include "framework/codec.h"
#include "main/snort_types.h"


namespace ip_util
{


SO_PUBLIC bool CheckIPV6HopOptions(const RawData&);

// NOTE:: data.next_prot_id MUST be set before calling this!!
void CheckIPv6ExtensionOrder(CodecData& codec, const uint8_t proto);

} // namespace ipv6_util

#endif
