//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// port_utils.h derived from sfportobject.h by Marc Noron

#ifndef PORT_UTILS_H
#define PORT_UTILS_H

#include "framework/bits.h"
#include "protocols/packet.h"
#include "utils/sflsq.h"

struct PortObject;
struct PortObjectItem;

int PortObjectBits(PortBitSet&, PortObject*);
SF_LIST* PortObjectItemListFromBits(const PortBitSet&, int n);

int* RuleListToSortedArray(SF_LIST*);

int integer_compare(const void* int1, const void* int2);

// global for printing so we don't put so many bytes on the stack
extern char po_print_buf[snort::MAX_PORTS];  // FIXIT-L delete this; replace with local stringstream

#endif

