//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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

// sftarget_hostentry.h author Steven Sturges

#ifndef SFTARGET_HOSTENTRY_H
#define SFTARGET_HOSTENTRY_H

#include "target_based/sftarget_reader.h"

/* API for HostAttributeEntry 'class' */

#if 0
bool hasProtocol(const HostAttributeEntry*, int ipprotocol, int protocol, int application);
#endif

SnortProtocolId get_snort_protocol_id_from_host_table(
    const HostAttributeEntry*, int ipprotocol, uint16_t port, char direction);

#endif

