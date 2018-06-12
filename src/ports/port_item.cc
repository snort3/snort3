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

// port_item.cc derived from sfportobject.h by Marc Noron

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "port_item.h"

#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;

/*
 * Create a new PortObjectItem
 */
PortObjectItem* PortObjectItemNew()
{
    PortObjectItem* poi = (PortObjectItem*)snort_calloc(sizeof(PortObjectItem));
    return poi;
}

/*
 * Free a PortObjectItem
 */
void PortObjectItemFree(PortObjectItem* poi)
{
    if (poi)
        snort_free(poi);
}

/*
    Dup a PortObjectItem
*/
PortObjectItem* PortObjectItemDup(PortObjectItem* poi)
{
    PortObjectItem* poinew;

    if ( !poi )
        return nullptr;

    poinew = PortObjectItemNew();
    if ( !poinew )
        return nullptr;

    memcpy(poinew,poi,sizeof(PortObjectItem));

    return poinew;
}

/*
   PortObjects should be normalized, prior to testing
*/
int PortObjectItemsEqual(PortObjectItem* a, PortObjectItem* b)
{
    return ( a->lport == b->lport && a->hport == b->hport );
}

/*
   Print port items.  Used internally by sfportobject.c.
   Buffer assumed trusted.
*/
void PortObjectItemPrint(PortObjectItem* poi, char* dstbuf, int bufsize)
{
    SnortSnprintfAppend(dstbuf, bufsize, " ");

    if ( poi->negate )
        SnortSnprintfAppend(dstbuf, bufsize, "!");

    if ( poi->any() )
        SnortSnprintfAppend(dstbuf, bufsize, "any");

    else if ( poi->one() )
        SnortSnprintfAppend(dstbuf, bufsize, "%hu", poi->lport);

    else
        SnortSnprintfAppend(dstbuf, bufsize, "%hu:%hu",poi->lport,poi->hport);
}

