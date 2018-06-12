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

#include <cassert>

#include "port_object.h"

#include "log/messages.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "port_group.h"
#include "port_item.h"
#include "port_utils.h"

using namespace snort;

//-------------------------------------------------------------------------
// PortObject - public
//-------------------------------------------------------------------------

PortObject* PortObjectNew()
{
    PortObject* po = (PortObject*)snort_calloc(sizeof(PortObject));
    po->item_list =(SF_LIST*)sflist_new();
    po->rule_list =(SF_LIST*)sflist_new();
    return po;
}

void PortObjectFree(void* pv)
{
    assert(pv);
    PortObject* po = (PortObject*)pv;

    if ( po->name )
        snort_free(po->name);

    if ( po->item_list)
        sflist_free_all(po->item_list, snort_free);

    if ( po->rule_list)
        sflist_free_all(po->rule_list, snort_free);

    if (po->group )
        PortGroup::free(po->group);

    snort_free(po);
}

void PortObjectFinalize(PortObject* po)
{
    sflist_free_all(po->item_list, snort_free);
    sflist_free_all(po->rule_list, snort_free);

    po->item_list = nullptr;
    po->rule_list = nullptr;
}

/*
 *  Set the name of the Port Object
 */
int PortObjectSetName(PortObject* po, const char* name)
{
    if ( !po )
        return -1;

    if ( !name )
        return -1;

    /* free the old name */
    if (po->name)
        snort_free(po->name);

    /* alloc a new name */
    po->name = snort_strdup(name);
    return 0;
}

/*
 * Add a PortObjectItem to a PortObject
 */
int PortObjectAddItem(PortObject* po, PortObjectItem* poi, int* errflag)
{
    PortObjectItem* p;
    SF_LNODE* pos = nullptr;

    if (!po || !poi)
        return 0;

    if (errflag)
        *errflag = 0;

    /* Make sure this is not a duplicate */
    for (p=(PortObjectItem*)sflist_first(po->item_list,&pos);
        p != nullptr;
        p=(PortObjectItem*)sflist_next(&pos) )
    {
        if ((p->lport == poi->lport) && (p->hport == poi->hport))
            snort::ParseWarning(WARN_RULES, "duplicate ports in list");
    }

    sflist_add_tail(po->item_list, poi);
    return 0;
}

/*
 * Add a PortObjectItem to a PortObject
 */
int PortObjectAddPortObject(PortObject* podst, PortObject* posrc, int* errflag)
{
    PortObjectItem* po;
    SF_LNODE* pos = nullptr;
    int ret = 0;

    if (errflag)
        *errflag = 0;

    for (po=(PortObjectItem*)sflist_first(posrc->item_list, &pos);
        po != nullptr;
        po=(PortObjectItem*)sflist_next(&pos) )
    {
        PortObjectItem* poi = PortObjectItemDup(po);
        if ((ret = PortObjectAddItem(podst, poi, errflag)) != 0)
        {
            PortObjectItemFree(poi);
            return ret;
        }
    }

    return ret;
}

int PortObjectAddPort(PortObject* po, int port)
{
    return PortObjectAddRange(po, port, port);
}

int PortObjectAddRange(PortObject* po, int lport, int hport)
{
    PortObjectItem* poi = PortObjectItemNew();

    if ( !poi )
        return -1;

    poi->lport = (unsigned short)lport;
    poi->hport = (unsigned short)hport;

    sflist_add_tail(po->item_list, poi);
    return 0;
}

int PortObjectAddRule(PortObject* po, int rule)
{
    int* pruleid;

    //LogMessage("Adding Rule %d to Port Object '%s'\n",rule,po->name);
    if ( !po )
        return -1;

    if ( !po->rule_list )
        return -1;

    /* Add rule index to rule list */
    pruleid = (int*)snort_calloc(sizeof(int));
    *pruleid = rule;

    sflist_add_tail(po->rule_list, pruleid);
    return 0;
}

int PortObjectAddPortAny(PortObject* po)
{
    if (!po->name)
        po->name = snort_strdup("any");

    return PortObjectAddRange(po, 0, SFPO_MAX_PORTS-1);
}

/*
 * Dup the PortObjects Item List, RuleList, and Name
 */
PortObject* PortObjectDup(PortObject* po)
{
    SF_LNODE* lpos = nullptr;
    PortObject* ponew = PortObjectNew();

    if ( !ponew )
        return nullptr;

    /* Dup the Name */
    if ( po->name )
        ponew->name = snort_strdup(po->name);
    else
        ponew->name = snort_strdup("dup");

    /* Dup the Item List */
    if ( po->item_list )
    {
        for (PortObjectItem* poi =(PortObjectItem*)sflist_first(po->item_list,&lpos);
            poi != nullptr;
            poi =(PortObjectItem*)sflist_next(&lpos) )
        {
            PortObjectItem* poinew = PortObjectItemDup(poi);

            if (!poinew)
            {
                PortObjectFree(ponew);
                return nullptr;
            }

            PortObjectAddItem(ponew, poinew, nullptr);
        }
    }

    /* Dup the input rule list */
    if ( po->rule_list )
    {
        for (int* prid  = (int*)sflist_first(po->rule_list,&lpos);
            prid != nullptr;
            prid  = (int*)sflist_next(&lpos) )
        {
            int* prule = (int*)snort_calloc(sizeof(int));
            *prule = *prid;
            sflist_add_tail(ponew->rule_list,prule);
        }
    }

    return ponew;
}

/*
 * Dup the PortObjects Item List, and Name
 */
PortObject* PortObjectDupPorts(PortObject* po)
{
    SF_LNODE* lpos = nullptr;
    PortObject* ponew = PortObjectNew();

    if ( !ponew )
        return nullptr;

    /* Dup the Name */
    if ( po->name )
        ponew->name = snort_strdup(po->name);
    else
        ponew->name = snort_strdup("dup");

    /* Dup the Item List */
    if ( po->item_list )
    {
        for (PortObjectItem* poi =(PortObjectItem*)sflist_first(po->item_list,&lpos);
            poi != nullptr;
            poi =(PortObjectItem*)sflist_next(&lpos) )
        {
            PortObjectItem* poinew = PortObjectItemDup(poi);

            if (!poinew)
            {
                PortObjectFree(ponew);
                return nullptr;
            }
            PortObjectAddItem(ponew, poinew, nullptr);
        }
    }
    return ponew;
}

/*
 *   Normalize a port object
 *
 *   The reduces multiple references to a given port to a single unique reference
 *   This function should be used on each PortObject, once it's completed. After
 *   the normalized PortObject is created, the input PortObject may be deleted.
 */
int PortObjectNormalize(PortObject* po)
{
    if ( PortObjectHasAny (po) )
        return 0;   /* ANY =64K */

    PortBitSet parray;
    int nports = PortObjectBits(parray, po);

    sflist_free_all(po->item_list, snort_free);
    po->item_list = PortObjectItemListFromBits(parray, SFPO_MAX_PORTS);

    return nports;
}

/*
   PortObjects should be normalized, prior to testing
*/
int PortObjectEqual(PortObject* a, PortObject* b)
{
    PortObjectItem* pa;
    PortObjectItem* pb;
    SF_LNODE* posa;
    SF_LNODE* posb;

    if ( a->item_list->count != b->item_list->count )
        return 0;

    pa = (PortObjectItem*)sflist_first(a->item_list,&posa);
    pb = (PortObjectItem*)sflist_first(b->item_list,&posb);

    while ( pa && pb )
    {
        if ( !PortObjectItemsEqual(pa, pb) )
            return 0;

        pa = (PortObjectItem*)sflist_next(&posa);
        pb = (PortObjectItem*)sflist_next(&posb);
    }

    if ( pa || pb ) /* both are not done - cannot match */
        return 0;

    return 1; /* match */
}

/*
 * Calcs number of ports in this object,
 * object do not have to  be normalized,
 * but if the same ports are referenced
 * twice, the count will be off.
 *
 * returns:
 *  any = -1
 *  0   = none/empty
 *  >0  = number of ports
*/
int PortObjectPortCount(PortObject* po)
{
    SF_LNODE* cursor;
    int cnt=0;

    if ( !po )
        return 0;

    for (PortObjectItem* poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&cursor) )
    {
        if ( poi->any() )
            return -1;

        int nports = poi->hport - poi->lport + 1;

        if ( poi->negate )
            cnt -= nports;
        else
            cnt += nports;
    }

    if ( cnt < 0 )
    {
        /* we have a pure not port or port range
         *
         * !80    = -1, add 64K (65535 -1 = 65534)
         * !80:81 = -2, (65535 - 2 = 65533)
         *
         * [:1023,!80]  = 1024 - 1 = 1023 ports
         *
         */
        cnt += SFPO_MAX_PORTS;  /* add back in the acceptable ports */
    }

    return cnt;
}

/*
 * This does NOT return true if the object is an ANY port
*/
int PortObjectHasPort(PortObject* po, int port)
{
    PortObjectItem* poi;
    SF_LNODE* cursor;

    if ( !po )
        return 0;

    for (poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&cursor) )
    {
        if ( poi->any() )
            return 0;

        // FIXIT-L need to check range based on flag???
        if ( (uint16_t)port >= poi->lport &&
            (uint16_t)port <= poi->hport )
            return 1;

        if ( poi->negate )
            return 1;
    }
    return 0;
}

void PortObjectToggle(PortObject* po)
{
    PortObjectItem* poi;
    SF_LNODE* pos;

    if (!po)
        return;

    for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&pos) )
    {
        poi->negate = !poi->negate;
    }
}

int PortObjectIsPureNot(PortObject* po)
{
    PortObjectItem* poi;
    SF_LNODE* cursor;
    int cnt=0;

    if ( !po )
        return 0;

    for (poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&cursor) )
    {
        cnt++;
        if ( !poi->negate )
            return 0;
    }

    if ( cnt == 0 )
        return 0;

    return 1;
}

int PortObjectHasAny(PortObject* po)
{
    PortObjectItem* poi;
    SF_LNODE* cursor;

    if ( !po )
        return 0;

    for (poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&cursor) )
    {
        if ( poi->any() )
            return 1;
    }
    return 0;
}

/*
 *  Removes Ports in B from A ... A = A - B
 */
int PortObjectRemovePorts(PortObject* a,  PortObject* b)
{
    PortBitSet pA, pB;

    PortObjectBits(pA, a);
    PortObjectBits(pB, b);

    pA &= ~pB;

    /* Release the old port list */
    sflist_free_all(a->item_list, snort_free);

    /* Replace the old PortObject list */
    a->item_list = PortObjectItemListFromBits(pA, SFPO_MAX_PORTS);

    return 0;
}

/*
   Dup and Append PortObjectItems from pob to poa
*/
PortObject* PortObjectAppend(PortObject* poa, PortObject* pob)
{
    SF_LNODE* cursor;

    for ( PortObjectItem* poib = (PortObjectItem*)sflist_first(pob->item_list, &cursor);
        poib!= nullptr;
        poib = (PortObjectItem*)sflist_next(&cursor) )
    {
        PortObjectItem* poia = PortObjectItemNew();

        if (!poia)
            return nullptr;

        memcpy(poia,poib,sizeof(PortObjectItem));

        sflist_add_tail(poa->item_list,poia);
    }
    return poa;
}

void PortObjectPrint(PortObject* po)
{
    PortObjectPrintEx(po, rule_index_map_print_index);
}

void PortObjectPrintPortsRaw(PortObject* po)
{
    PortObjectItem* poi = nullptr;
    SF_LNODE* pos = nullptr;
    char* buf;
    int bufsize;

    /* Need to buffer the string so we only do one LogMessage,
     * due to syslog output.  The largest string needed to represent
     * each portobject is the length required to represent:
     * " unknown port type @ 0x<8 max bytes>" (See PortObjectItemPrint), or:
     * 30 bytes.  For the entire list, need room for spaces and brackets and
     * potential negations. Or:
     *      list_size * (30 + 1space_for_each_element, +
     *       1potential_negation) + surrounding_whitespace + brackets + NULL */

    bufsize = po->item_list->count * (30 + 1 + 1) + 5;
    buf = (char*)snort_calloc(bufsize);
    SnortSnprintfAppend(buf, bufsize, " [");

    for (poi=(PortObjectItem*)sflist_first(po->item_list, &pos);
        poi != nullptr;
        poi=(PortObjectItem*)sflist_next(&pos) )
    {
        PortObjectItemPrint(poi, buf, bufsize);
    }

    SnortSnprintfAppend(buf, bufsize, " ]");

    snort::LogMessage("%s", buf);

    snort_free(buf);
}

/*
   Print Port Object - Prints input ports and rules (uncompiled)
    ports
    rules (input by user)
*/
void PortObjectPrintEx(PortObject* po, po_print_f print_index_map)
{
    PortObjectItem* poi = nullptr;
    SF_LNODE* pos = nullptr;
    int k=0;
    int* rlist = nullptr;
    unsigned i;

    /* static for printing so we don't put so many bytes on the stack */
    static char po_print_buf[snort::MAX_PORTS];  // FIXIT-L delete this; replace with local stringstream

    int bufsize = sizeof(po_print_buf);
    po_print_buf[0] = '\0';

    if ( !po )
        return;

    if ( !po->rule_list )
        return;

    if ( !po->rule_list->count )
        return;

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject ");

    if ( po->name )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "%s ", po->name);
    }

    SnortSnprintfAppend(po_print_buf, bufsize,
        " Id:%d  Ports:%u Rules:%u\n {\n",
        po->id, po->item_list->count,po->rule_list->count);

    SnortSnprintfAppend(po_print_buf, bufsize, "  Ports [\n  ");

    if ( PortObjectHasAny(po) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
        for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != nullptr;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            PortObjectItemPrint(poi, po_print_buf, bufsize);
        }
    }
    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n");

    rlist = RuleListToSortedArray(po->rule_list);
    if (!rlist )
    {
        return;
    }

    SnortSnprintfAppend(po_print_buf, bufsize, "  Rules [ \n ");
    for (i=0; i<po->rule_list->count; i++)
    {
        if ( print_index_map )
        {
            print_index_map(rlist[i], po_print_buf, bufsize);
        }
        else
        {
            SnortSnprintfAppend(po_print_buf, bufsize, " %d",rlist[i]);
        }
        k++;
        if ( k == 25 )
        {
            k=0;
            SnortSnprintfAppend(po_print_buf, bufsize, " \n ");
        }
    }
    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n }\n");

    snort::LogMessage("%s", po_print_buf);
    snort_free(rlist);
}

