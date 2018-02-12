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

// port_item.h derived from sfportobject.h by Marc Noron

#ifndef PORT_ITEM_H
#define PORT_ITEM_H

#include <cstdint>

#define SFPO_MAX_LPORTS 500
#define SFPO_MAX_PORTS 65536

//-------------------------------------------------------------------------
// Port Object Item supports
// port, lowport:highport (inclusive)
//
// so it indicates a single port, a consecutive range of ports, or the any
// port.  can also be negated.
//-------------------------------------------------------------------------

struct PortObjectItem
{
    bool any()
    { return !negate and lport == 0 and hport == SFPO_MAX_PORTS-1; }

    bool one()
    { return lport == hport; }

    bool negate;

    uint16_t hport;   /* hi port */
    uint16_t lport;   /* lo port */
};

PortObjectItem* PortObjectItemNew();
void PortObjectItemFree(PortObjectItem*);
PortObjectItem* PortObjectItemDup(PortObjectItem*);
int PortObjectItemsEqual(PortObjectItem* a, PortObjectItem* b);
void PortObjectItemPrint(PortObjectItem*, char* dstbuf, int bufsize);

#endif

