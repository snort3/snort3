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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "port_utils.h"

#include "utils/util.h"

#include "port_item.h"
#include "port_object.h"

using namespace snort;

//-------------------------------------------------------------------------
// bitset conversions
//-------------------------------------------------------------------------

/*
 *  Build a PortMap Char Array
 *  returns:  0 if an  ANY port.
 *            n number of unique ports.
 */
int PortObjectBits(PortBitSet& parray, PortObject* po)
{
    if ( !po || PortObjectHasAny (po) )
        return 0;  /* ANY =64K */

    int cnt = 0;
    unsigned not_cnt = 0;
    PortObjectItem* poi;
    SF_LNODE* pos;

    for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&pos) )
    {
        /* Add ports that are not NOT'd */
        if ( poi->negate )
        {
            not_cnt++;
            continue;
        }

        if ( poi->any() )
            continue;

        for ( int i = poi->lport; i <= poi->hport; i++ )
        {
            if ( !parray[i] )
                cnt++;
            parray[i] = true;
        }
    }

    /* Remove any NOT'd ports that may have been added above */
    for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&pos) )
    {
        if ( !poi->negate  )
            continue;

        if ( poi->any() )
            continue;

        for ( int i = poi->lport; i <= poi->hport; i++ )
        {
            if ( parray[i] )
                cnt--;
            parray[i] = false;
        }
    }

    /* A pure Not list */
    if ( po->item_list->count == not_cnt )
    {
        /* enable all of the ports */
        parray.set();
        cnt += parray.count();

        /* disable the NOT'd ports */
        for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != nullptr;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            if ( !poi->negate  )
                continue; /* should not happen */

            if ( poi->any() )
                continue;

            for ( int i = poi->lport; i <= poi->hport; i++ )
            {
                if ( parray[i] )
                    cnt--;
                parray[i] = false;
            }
        }
    }

    return cnt;
}

SF_LIST* PortObjectItemListFromBits(const PortBitSet& parray, int n)
{
    SF_LIST* plist = sflist_new();
    int nports = parray.count();

    if ( !plist )
        return nullptr;

    for (int i = 0; i < n && nports > 0; i++)
    {
        if ( parray[i] == 0 )
            continue;

        int lport, hport;

        /* Either a port or the start of a range */
        lport = hport = i;
        nports--;

        for (i++; i<n; i++)
        {
            if ( parray[i] )
            {
                hport = i;
                nports--;
                continue;
            }
            break;
        }

        PortObjectItem* poi = PortObjectItemNew();

        if ( !poi )
        {
            sflist_free_all(plist, snort_free);
            return nullptr;
        }

        poi->lport =(unsigned short)lport;
        poi->hport =(unsigned short)hport;
        sflist_add_tail(plist, poi);
     }

    return plist;
}

//-------------------------------------------------------------------------
// sorting
//-------------------------------------------------------------------------

int integer_compare(const void* arg1, const void* arg2)
{
    if ( *(const int*)arg1 <  *(const int*)arg2 )
        return -1;

    if ( *(const int*)arg1 >  *(const int*)arg2 )
        return 1;

    return 0;
}

int* RuleListToSortedArray(SF_LIST* rl)
{
    SF_LNODE* pos = nullptr;
    int* prid;
    int* ra;
    int k=0;

    if ( !rl )
        return nullptr;

    if (!rl->count)
        return nullptr;

    ra = (int*)snort_calloc(rl->count, sizeof(int));

    for ( prid = (int*)sflist_first(rl,&pos);
        prid!= nullptr && k < (int)rl->count;
        prid = (int*)sflist_next(&pos) )
    {
        ra[k++] = *prid;
    }

    /* sort the array */
    qsort(ra,rl->count,sizeof(int),integer_compare);

    return ra;
}

//-------------------------------------------------------------------------
// printing
//-------------------------------------------------------------------------

char po_print_buf[snort::MAX_PORTS];

