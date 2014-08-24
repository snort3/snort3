/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

/*
   sfportobject.c

   author:  marc norton
   date:    11/05/2005

   description:

   Port objects provides support for generic ports lists comprised of
   individual ports, port ranges, and negation of ports and port ranges.

   Port lists require a somewhat more complex scheme to determine the proper
   grouping of rules for each port while minimizing the number of rule groups
   created. We can use a single group of rules in the multi-pattern detection phase,
   however that can have a huge impact on performance.  Instead we try to create
   a smaller grouping of rules that might be applicable to each port.

   As rules are defined using port ranges, and port lists there will be port
   overlapps between rules. This requires us to determine whether we should
   create one larger rule group to apply to all relevant ports, or to
   create multiple rule groups and apply the smallest applicable one to
   each port. In practice snort has some rules which span almost all 64K ports
   which might cause all rules in all port-rule groups to be merged into one set
   unless we apply a more complex logic than simply merging rule-port groups
   with common ports.  This is the problem addressed by the sfportobject
   module.

   port list examples of acceptable usage:

   - var has been overloaded, if it includes _port we add as a port-object also.
   var http_ports 80
   var http_range_ports 80:81
   var http_list_ports  [80,8080,8138]

   - portvar has been added to indicate portvariables, this form does not require _port
   portvar http 80
   portvar http_range 80:81
   portvar http_list  [80,8080,8138]

   80
   $http
   !90
   80:81
   $http_range
   !90:91
   [80,8080,8138]
   $http_list
   [$http,$http_list]
   [2001,2008,20022,8100:8150,!8121,!8123]
   [!any] - uhhh, why do people ask about this ?

   Rules are defined using a port, a port-range or a list of these, we call
   these port objects.

   As rules are loaded we generate some large rule counts on some ports, and
   small rule counts on most ports.  If for each port you build a list of
   rules on that port, we may end up with some ports with a large rule set that
   differs by the addition of a few rules on each port (relative to the group sizes)
   we don't want to generate compeletely different rule groups for these as that
   would than generate multiple large state machines for the multi-pattern matching
   phase of the detection engine which in turn could use a lot of memory.

   It turns out that one scheme, the one used herein, provides some blending
   of rule groups to minimize memory, and tries to minimize large group sizes
   to keep performance more optimal - although this is at the expense of memory.

   --- Port variables
   Var - has been overloaded. If it's name includes _port as part of the var name it is
   added to the PortVarTable.
   PortVar - has been added. These are always added to the PortVarTable.

   --- Loading Port lists and rules
   PortTables - we support src and dst tables for tcp/udp/icmp/ip/arp rules.
   PortVar References - we dup the PortVar entries as needed into each table if referenced,
   so HTTP_PORTS for tcp and udp contain different rules.  If a rule references a PortVar
   we look it up in the table, if its not present we dup it from the PortVarTable, otherwise
   we just add the rule index to the PortVar HTTP_PORTS in the proper table. If a PortVar
   is not used to specify a Port entry in a rule we create a temp port-object, and check if
   it's port-list is already in the table. If it's not we make the temp port-object the
   permanent entry in the  table. If it is, we just add the rule index to the existing entry,
   and delete the temp port-object. When the rules are done loading we should have a set of
   port-objects with port-lists that differ by at least one port.  The next step handles the
   cases where we have multiple port-objects with at least one common port.

   --- Merging Ports and Rules
   We maintain for each port a list of port objects and their rules that apply
   to it. This allows us to view combining the rules associated with each port
   object using a few heuristics. A list of port objects applicable to each port
   presents rules in one of four catagories:

   1) a single port object, and all rules associated with it.
   2) multiple port objects each with a small set of rules associated with it.
   3) one port object with a large rule set, and one or more port objects
      with a small set of rules associated with each.
   4) multiple port objects with large rule sets, and zero or more port objects
      each with a small set of rules associated with it.

    We process these four categories as follows:

    1) -a single port object (large or small)
        do nothing, each port referencing this port object is complete.
    2) -multiple small port objects
        merge the rules for all port objects into one virtual object,
       for each port in this category lookup it's combined port object
       to see if it's already defined, if not create one.  This way
       all ports that have the same port groups point to the same virtual
       port object.
    3) -one large port object, and one or more small port objects
        add the small rule groups into the large rule set, using the existing
       port object.
    4) -multiple large port objects and zero or more small port objects
        merge the large port objects into a virtual port object and
       add all rules from both large and small sets into it's rule set.
       we use the combined large group ports to form a key, so any ports
       referencing just these large rule groups, and some small ones
       will be recognized as the same.  This handles cases where we have
       2,3,4.etc large rule groups combined.  Any time we see a 'n' grouping
       of the same large rule sets we'll look it up and point to it for that
       port.

    To determine when a port object has a large rule set or a small one we use
    a simple threshold value. In theory the larger this value is the more
    merging of rules in category 2 and 3 will occur. When this value is
    small category 4 should become a more prevalent situation.  However,
    the behavior of groupings for a given threshold can change as more rules
    are added to port groups.  Therefore generous statistics are printed after
    the rules and port objects are compiled into their final groupings.


  Procedure for using PortLists

  1) Process Var's as PortVar's and standard Var's (for now). This allows
  existing snort features to work, with the Var's.  Add in the PortVar support
  to parse the Var input into PortObjects, and add these to the PortVartable.

  2) Read Rules
    a) Read port numbers and lists
        1) Dereference PortVar/Var Names if any are referenced.
    b) Create a Port Object
    c) Test if this Port object exists already,
        1) If so, add the sid to it.
        2) If not add it ....



  Notes:

    All any-any port rules are managed separately, and added in to the final
    rules lists of each port group after this analysis. Rules defined with
    ranges are no longer considered any-any rules for the purpose of organizing
    port-rule groupings.  This should help prevent some cross fertilization of
    rule groups with rules that are unneccessary, this causes rule group
    sizes to bloat and performance to slow.

  Hierarchy:

    PortTable -> PortObject's

    PortVar -> PortObject ( These are pure, and are dup'ed for use in the PortTables )

    PortObject -> PortObjectItems (port or port range)

*/

#include "sfportobject.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include <memory>

#include "snort_types.h"
#include "snort.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "detection/sfrim.h"
#include "parser.h"
#include "util.h"

#define PO_EXTRA_RULE_CNT 25
#define PTBL_LRC_DEFAULT 10
#define PO_INIT_ID 1000000
#define PO_HASH_TBL_ROWS 10000

/*
   Hash Key Comparisons for treating PortObjects as Keys

   return values memcmp style
*/
static int PortObject_keycmp(const void *a , const void *b, size_t)
{
    return !PortObjectEqual( *(PortObject**)a, *(PortObject**)b );
}

/*
 *  plx_t is a variable sized array of pointers
 */
typedef struct {
    int     n;
    void ** p;
}plx_t;

static plx_t * plx_new( void * pv_array[], int n )
{
    plx_t * p;
    int i;

    if(!pv_array || n < 0)
        return NULL;

    p = (plx_t*)SnortAlloc(sizeof(plx_t));

    p->p = (void**)SnortAlloc(n * sizeof(void*));

    p->n = n;
    for(i=0;i<n;i++)
    {
        p->p[i] = pv_array[i];
    }
    return p;
}

static void plx_free(void * p )
{
    plx_t * plx=(plx_t*)p;

    if( !plx ) return;
    if( plx->p ) free(plx->p);
    free( p );
}

#ifdef DEBUG_MSGS
static void plx_print(plx_t * p)
{
    DEBUG_WRAP(
        int i;
        DebugMessage(DEBUG_PORTLISTS, "plx-n=%d\n", p->n);
        for(i=0;i<p->n;i++)
            DebugMessage(DEBUG_PORTLISTS, "plx[%d]=%lu\n", i, p->p[i]);
    );
}
#endif

/*
 *   hash function for plx_t types
 */
static unsigned plx_hash(SFHASHFCN * p, unsigned char *d, int)
{
    unsigned k, hash = p->seed;
    int i;
    plx_t* plx;

    plx = *(plx_t**)d;

    for(i=0;i<plx->n;i++)
    {
       unsigned char * pc_ptr = (unsigned char*)&plx->p[i];
       for(k=0;k<sizeof(void*);k++)
       {
          hash *=  p->scale;
          hash +=  pc_ptr[k];
       }
    }
    return hash ^ p->hardener;
}


/* for sorting an array of pointers */
static inline int p_keycmp( const void *a , const void *b )
{
    if( *(unsigned long**)a < *(unsigned long**)b ) return -1;
    if( *(unsigned long**)a > *(unsigned long**)b ) return  1;

    return 0; /* they are equal */
}


/*
   Hash Key Comparisons for treating plx_t types as Keys

   return values memcmp style

   this only needs to produce 0 => exact match, otherwise not.
   -1, and +1 are not strictly needed, they could both return
   a non zero value for the purposes of hashing and searching.
*/
static int plx_keycmp( const void *a , const void *b, size_t )
{
    int i, cmp;
    plx_t * pla = *(plx_t**)a;
    plx_t * plb = *(plx_t**)b;

    if( pla->n < plb->n ) return -1;

    if( pla->n > plb->n ) return  1;

    for(i=0;i<pla->n;i++)
    {
        if((cmp = p_keycmp(&pla->p[i], &plb->p[i])) != 0)
            return cmp;
    }

    return 0; /* they are equal */
}


/* global for printing so we don't put so many bytes
 * on the stack */
static char po_print_buf[MAXPORTS];  // FIXIT-L delete this; replace with local stringstream

/*
   PORT OBJECT FUNCTIONS
*/

/*
    Create a new PortObject
*/
PortObject * PortObjectNew(void)
{
    PortObject *po = (PortObject *)SnortAlloc(sizeof(PortObject));

    po->item_list =(SF_LIST*) sflist_new();

    if( !po->item_list )
    {
        free( po );
        return 0;
    }

    po->rule_list =(SF_LIST*) sflist_new();
    if( !po->rule_list )
    {
        sflist_free_all( po->item_list, free );
        free( po );
        return 0;
    }

    return po;
}

/* This is the opposite of ntohl/htonl defines, and does the
 * swap on big endian hardware */
#ifdef WORDS_BIGENDIAN
#define SWAP_BYTES(a) \
    ((((uint32_t)(a) & 0xFF000000) >> 24) | \
     (((uint32_t)(a) & 0x00FF0000) >> 8) | \
     (((uint32_t)(a) & 0x0000FF00) << 8) | \
     (((uint32_t)(a) & 0x000000FF) << 24))
#else
#define SWAP_BYTES(a) (a)
#endif
static unsigned po_rule_hash_func(SFHASHFCN *p, unsigned char *k, int n)
{
    unsigned char *key;
    int ikey = *(int*)k;

    /* Since the input is really an int, put the bytes into a normalized
     * order so that the hash function returns consistent results across
     * on BE & LE hardware. */
    ikey = SWAP_BYTES(ikey);

    /* Set a pointer to the key to pass to the hashing function */
    key = (unsigned char *)&ikey;

    return sfhashfcn_hash(p, key, n);
}

/*
    Create a new PortObject2
*/
PortObject2 * PortObject2New(int nrules)
{
    PortObject2 *po = (PortObject2 *)SnortAlloc(sizeof(PortObject2));

    po->item_list =(SF_LIST*) sflist_new();

    if( !po->item_list )
    {
        free( po );
        return 0;
    }

    po->rule_hash =(SFGHASH*) sfghash_new(nrules,sizeof(int),0,free /* frees data - should be rule id ptrs == (int*) */);
    if( !po->rule_hash )
    {
        sflist_free_all( po->item_list, free );
        free( po );
        return 0;
    }

    /* Use hash function defined above for hashing the key as an int. */
    sfghash_set_keyops(po->rule_hash, po_rule_hash_func, memcmp);

    //sfhashfcn_static( po->rule_hash->sfhashfcn ); /* TODO: Leave this in, else we get different events */

    return po;
}
/*
 *  Set the name of the Port Object
 */
int PortObjectSetName(PortObject * po, const char * name)
{
    if( !po )
        return -1;

    if( !name )
        return -1;

    /* free the old name */
    if(po->name)
        free(po->name);

    /* alloc a new name */
    po->name = SnortStrdup(name);
    if( !po->name )
        return -1;

    return 0;
}

/*
 * Free a PortObjectItem
 */
void PortObjectItemFree (PortObjectItem * poi)
{
    if(poi) free(poi);
}

/*
 *  Free the PortObject
 */
void PortObjectFree( void * pvoid )
{
    PortObject * po = (PortObject *)pvoid;
    DEBUG_WRAP(static int pof_cnt = 0; pof_cnt++;);

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"PortObjectFree-Cnt: %d ptr=%p\n",pof_cnt,pvoid););

    if( !po ) return ;

    if( po->name ) free (po->name );
    if( po->item_list) sflist_free_all( po->item_list, free );
    if( po->rule_list) sflist_free_all( po->rule_list, free );

    if (po->data && po->data_free)
    {
        po->data_free(po->data);
    }

    free( po );
}
/*
 *  Free the PortObject2
 */
void PortObject2Free( void * pvoid )
{
    PortObject2 * po = (PortObject2 *)pvoid;
    DEBUG_WRAP(static int pof2_cnt = 0; pof2_cnt++;);

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"PortObjectFree2-Cnt: %d ptr=%p\n",pof2_cnt,pvoid););

    if( !po ) return;

    if( po->name ) free (po->name );
    if( po->item_list) sflist_free_all( po->item_list, free );
    if( po->rule_hash) sfghash_delete( po->rule_hash );
    if (po->bitop)
    {
        boFreeBITOP(po->bitop);
        free(po->bitop);
    }

    if (po->data && po->data_free)
    {
        po->data_free(po->data);
    }

    free( po );
}

/*
 * Create a new PortObjectItem
 */
PortObjectItem * PortObjectItemNew(void)
{
    PortObjectItem *poi = (PortObjectItem *)SnortAlloc(sizeof(PortObjectItem));

    return poi;
}

/*
 * Add a PortObjectItem to a PortObject
 */
int PortObjectAddItem( PortObject * po, PortObjectItem * poi, int *errflag)
{
    PortObjectItem *p;
    SF_LNODE       *pos = NULL;

    if(!po || !poi) return 0;

    if(errflag) *errflag = 0;

    /* Make sure this is not a duplicate */
    for(p=(PortObjectItem*)sflist_first(po->item_list,&pos);
        p != 0;
        p=(PortObjectItem*)sflist_next(&pos) )
    {
        if((p->lport == poi->lport) && (p->hport == poi->hport))
        {
            if(errflag) *errflag = POPERR_DUPLICATE_ENTRY;
            return -1; /* -1 chosen for consistency with sflist_add_tail */
        }
    }

    return sflist_add_tail( po->item_list, poi );
}

/*
 * Add a PortObjectItem to a PortObject
 */
int PortObjectAddPortObject(PortObject * podst, PortObject * posrc, int *errflag)
{
    PortObjectItem *po;
    SF_LNODE       *pos = NULL;
    int ret = 0;

    if(errflag) *errflag = 0;

    for(po=(PortObjectItem*)sflist_first(posrc->item_list, &pos);
        po != 0;
        po=(PortObjectItem*)sflist_next(&pos) )
    {
        PortObjectItem *poi = PortObjectItemDup(po);
        if((ret = PortObjectAddItem(podst, poi, errflag)) != 0)
        {
            PortObjectItemFree(poi);
            return ret;
        }
    }

    return ret;
}


/*
    Dup a PortObjectItem
*/
PortObjectItem * PortObjectItemDup( PortObjectItem * poi)
{
   PortObjectItem * poinew;

   if( !poi )
       return 0;

   poinew = PortObjectItemNew();
   if( !poinew )
       return 0;

   memcpy(poinew,poi,sizeof(PortObjectItem));

   return poinew;
}

/*
 * Dup the PortObjects Item List, RuleList, and Name
 */
PortObject * PortObjectDup( PortObject * po )
{
    PortObject     * ponew = NULL;
    PortObjectItem * poi = NULL;
    PortObjectItem * poinew = NULL;
    SF_LNODE       * lpos = NULL;
    int            * prid = NULL;
    int            * prule = NULL;

    ponew = PortObjectNew();
    if( !ponew )
        return 0;

    /* Dup the Name */
    if( po->name )
        ponew->name = strdup(po->name);
    else
        ponew->name = strdup("dup");

    if( !ponew->name )
    {
        free( ponew );
        return NULL;
    }

    /* Dup the Item List */
    if( po->item_list )
    {
      for(poi =(PortObjectItem*)sflist_first(po->item_list,&lpos);
          poi != NULL;
          poi =(PortObjectItem*)sflist_next(&lpos) )
      {
        poinew = PortObjectItemDup( poi );
        if(!poinew)
        {
            free( ponew->name );
            free( ponew );
              return 0;
        }

        PortObjectAddItem( ponew, poinew, NULL );
      }
    }

    /* Dup the input rule list */
    if( po->rule_list )
    {
      for(prid  = (int*)sflist_first(po->rule_list,&lpos);
          prid != 0;
          prid  = (int*)sflist_next(&lpos) )
      {
          prule = (int*)calloc(1,sizeof(int));
          if(!prule)
          {
             free( poinew );
             free( ponew->name );
             free( ponew );
             return NULL;
          }
          *prule = *prid;
          sflist_add_tail(ponew->rule_list,prule);
      }
    }

    return ponew;
}
/*
 * Dup the PortObjects Item List, and Name
 */
PortObject * PortObjectDupPorts( PortObject * po )
{
    PortObject     * ponew = NULL;
    PortObjectItem * poi = NULL;
    PortObjectItem * poinew = NULL;
    SF_LNODE       * lpos = NULL;

    ponew = PortObjectNew();
    if( !ponew )
        return 0;

    /* Dup the Name */
    if( po->name )
        ponew->name = strdup(po->name);
    else
        ponew->name = strdup("dup");

    if( !ponew->name )
    {
        free( ponew );
        return NULL;
    }

    /* Dup the Item List */
    if( po->item_list )
    {
      for(poi =(PortObjectItem*)sflist_first(po->item_list,&lpos);
          poi != NULL;
          poi =(PortObjectItem*)sflist_next(&lpos) )
      {
        poinew = PortObjectItemDup( poi );
        if(!poinew)
        {
            free(ponew);
            return NULL;
        }
        PortObjectAddItem( ponew, poinew, NULL );
      }
    }
    return ponew;
}

/*
 * Dup the PortObjects Item List, Name, and RuleList->RuleHash
 */
PortObject2 * PortObject2Dup( PortObject * po )
{
    PortObject2    * ponew = NULL;
    PortObjectItem * poi = NULL;
    PortObjectItem * poinew = NULL;
    SF_LNODE       * lpos = NULL;
    int            * prid = NULL;
    int            * prule = NULL;

    if( !po )
        return NULL;

    if( !po->rule_list )
        return NULL;

    ponew = PortObject2New(po->rule_list->count + PO_EXTRA_RULE_CNT);
    if( !ponew )
        return NULL;

    /* Dup the Name */
    if( po->name )
        ponew->name = strdup(po->name);
    else
        ponew->name = strdup("dup");

    if( !ponew->name )
    {
        free( ponew );
        return NULL;
    }

    /* Dup the Item List */
    if( po->item_list )
    {
      for(poi =(PortObjectItem*)sflist_first(po->item_list,&lpos);
          poi != NULL;
          poi =(PortObjectItem*)sflist_next(&lpos) )
      {
        poinew = PortObjectItemDup( poi );
        if(!poinew)
              return 0;

        PortObjectAddItem( (PortObject*)ponew, poinew, NULL );
      }
    }

    /* Dup the input rule list */
    if( po->rule_list )
    {
        for(prid  = (int*)sflist_first(po->rule_list,&lpos);
            prid != 0;
            prid  = (int*)sflist_next(&lpos) )
        {
              prule = (int*)calloc(1,sizeof(int));
              if(!prule)
              {
                 return NULL;
              }
              *prule = *prid;
              if( sfghash_add( ponew->rule_hash, prule, prule ) != SFGHASH_OK )
              {
                  free( prule );
              }
        }
    }

    return ponew;
}

/*
   Add a Port to a PortObject
*/
int PortObjectAddPort( PortObject * po, int port, int not_flag )
{
   PortObjectItem * poi;

   poi = PortObjectItemNew();
   if( !poi )
       return -1;

   poi->type = PORT_OBJECT_PORT;

   if( not_flag )
       poi->flags = PORT_OBJECT_NOT_FLAG;

   poi->lport = (unsigned short)port;
   poi->hport = (unsigned short)port;

   return  sflist_add_tail( po->item_list, poi );
}

/*
   Add a Port Range to a PortObject
*/
int PortObjectAddRange( PortObject * po, int lport, int hport, int not_flag )
{
   PortObjectItem * poi;

   poi = PortObjectItemNew();
   if( !poi )
       return -1;

   poi->type = PORT_OBJECT_RANGE;

   if( not_flag )
       poi->flags = PORT_OBJECT_NOT_FLAG;

   poi->lport = (unsigned short)lport;
   poi->hport = (unsigned short)hport;

   return  sflist_add_tail( po->item_list, poi );
}
/*
   Add ANY port
*/
int PortObjectAddPortAny( PortObject * po )
{
   PortObjectItem * poi;

   if(!po)
       return -1 ;

   poi = PortObjectItemNew();
   if( !poi )
       return -1;

   poi->type = PORT_OBJECT_ANY;

   poi->lport = 0;
   poi->hport = MAXPORTS-1;

   if(!po->name)
       po->name = strdup("any");

   if(!po->name)
   {
       free(poi);
       return -1;
   }
   return  sflist_add_tail( po->item_list, poi );
}

/*
 *  Check if we have any ANY ports
 */
int PortObjectHasAny (PortObject * po )
{
     PortObjectItem *poi;
     SF_LNODE* cursor;

     if( !po )
         return 0;

     for(poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&cursor) )
     {
         if( poi->type == PORT_OBJECT_ANY )
             return 1;
     }
     return 0;
}
int PortObjectHasNot (PortObject * po )
{
     PortObjectItem *poi;
     SF_LNODE* cursor;

     if( !po )
         return 0;

     for(poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&cursor) )
     {
         if ( poi->flags== PORT_OBJECT_NOT_FLAG) return 1;
     }
     return 0;
}
int PortObjectIsPureNot (PortObject * po )
{
     PortObjectItem *poi;
     SF_LNODE* cursor;
     int cnt=0;

     if( !po )
         return 0;

     for(poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&cursor) )
     {
         cnt++;
         if ( poi->flags != PORT_OBJECT_NOT_FLAG)
              return 0;
     }

     if( cnt == 0 ) return 0;

     return 1;
}

/*
 * This does NOT return true if the object is an ANY port
*/
int PortObjectHasPort (PortObject * po, int port )
{
     PortObjectItem *poi;
     SF_LNODE* cursor;

     if( !po )
         return 0;

     for(poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&cursor) )
     {
        switch( poi->type )
        {
        case PORT_OBJECT_ANY:
            return 0;

        case PORT_OBJECT_PORT:
            if( poi->lport == (uint16_t)(port&0xffff) )
                return 1;
            if( poi->flags & PORT_OBJECT_NOT_FLAG  )
                return 1;
            break;

        case PORT_OBJECT_RANGE:
            if( (uint16_t)port >= poi->lport &&
                (uint16_t)port <= poi->hport )
                return 1;
            if( poi->flags & PORT_OBJECT_NOT_FLAG  )
                return 1;
            break;
        }
     }
     return 0;
}
/*
 * This returns true if the object is an ANY port
 */
int PortObjectIncludesPort (PortObject * po, int port )
{
     PortObjectItem *poi;
     SF_LNODE* cursor;

     if( !po )
         return 0;

     for(poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&cursor) )
     {
        switch( poi->type )
        {
        case PORT_OBJECT_ANY:
            return 1;

        case PORT_OBJECT_PORT:
            if( poi->lport == (uint16_t)port )
                return 1;
            if( poi->flags & PORT_OBJECT_NOT_FLAG  )
                return 1;
            break;

        case PORT_OBJECT_RANGE:
            if( (uint16_t)port >= poi->lport &&
                (uint16_t)port <= poi->hport )
                return 1;
            if( poi->flags & PORT_OBJECT_NOT_FLAG  )
                return 1;
            break;
        }
     }
     return 0;
}

/*
 *  Locate a PortObject by Port number , this only locates the 1st one
 *  This was a hack fro testing....
 */
PortObject * PortTableFindPortObjectByPort(  PortTable * p , int port )
{
    PortObject * po;
    SF_LNODE   * pos;

    for(po =(PortObject*)sflist_first(p->pt_polist,&pos);
       po != NULL;
       po =(PortObject*)sflist_next(&pos) )
    {
        if( PortObjectHasPort ( po, port ) )
        {
            return po;
        }
    }

    return 0;
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
int PortObjectPortCount (PortObject * po )
{
     PortObjectItem *poi;
     SF_LNODE* cursor;
     int cnt=0;
     int nports;

     if( !po )
         return 0;

     for(poi=(PortObjectItem*)sflist_first(po->item_list, &cursor);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&cursor) )
     {
        switch( poi->type )
        {
        case PORT_OBJECT_ANY:
            return -1;

        case PORT_OBJECT_PORT:
            if( poi->flags & PORT_OBJECT_NOT_FLAG  )
            {
                cnt--;
            }
            else
            {
                cnt++;
            }
            break;

        case PORT_OBJECT_RANGE:
            nports = poi->hport - poi->lport + 1;
            if( poi->flags & PORT_OBJECT_NOT_FLAG  )
            {
                cnt-=nports;
            }
            else
            {
                cnt+=nports;
            }
        }
     }

     if( cnt < 0 )
     {
         /* we have a pure not port or port range
          *
          * !80    = -1, add 64K (65535 -1 = 65534)
          * !80:81 = -2, (65535 - 2 = 65533)
          *
          * [:1023,!80]  = 1024 - 1 = 1023 ports
          *
          */
         cnt += SFPO_MAX_PORTS; /* add back in the acceptable ports */
     }

     return cnt;
}

/*
 *  Build a PortMap Char Array
 *  returns:  0 if an  ANY port.
 *            n number of unique ports.
 */
char * PortObjectCharPortArray ( char * parray, PortObject * po, int * nports )
{
     int cnt = 0;
     unsigned not_cnt=0;
     PortObjectItem * poi;
     SF_LNODE * pos;

     if( !po || PortObjectHasAny ( po ) )
     {
         return 0; /* ANY =64K */
     }

     if( !parray )
     {
         parray = (char*) calloc(1,SFPO_MAX_PORTS);
         if( !parray )
             return 0;
     }

     for(poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&pos) )
     {
         /* Add ports that are not NOT'd */
         if( poi->flags & PORT_OBJECT_NOT_FLAG  )
         {
             not_cnt++;
             continue;
         }

         if( poi->type == PORT_OBJECT_PORT  )
         {
             if( !parray[poi->lport] )
                cnt++;

             parray[poi->lport] = 1;
         }

         else if( poi->type == PORT_OBJECT_RANGE )
         {
             int i;
             for(i=poi->lport;i<=poi->hport;i++)
             {
                if( !parray[i] )
                    cnt++;
                parray[i] = 1;
             }
         }
     }

     /* Remove any NOT'd ports that may have been added above */
     for(poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
         poi != 0;
         poi=(PortObjectItem*)sflist_next(&pos) )
     {
         if( !( poi->flags & PORT_OBJECT_NOT_FLAG)  )
             continue;

         if( poi->type == PORT_OBJECT_PORT  )
         {
            if( parray[poi->lport] )
                cnt--;

            parray[poi->lport] =0;
         }
         else if( poi->type == PORT_OBJECT_RANGE )
         {
            int i;

            for(i=poi->lport;i<=poi->hport;i++)
            {
               if( parray[i] )
               cnt--;
               parray[i] = 0;
            }
         }
     }


    /* A pure Not list */
    if( po->item_list->count == not_cnt )
    {
        int i;

        /* enable all of the ports */
        for(i=0;i<SFPO_MAX_PORTS;i++)
        {
            parray[i] =1;
            cnt++;
        }

        /* disable the NOT'd ports */
        for(poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != 0;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            if( !( poi->flags & PORT_OBJECT_NOT_FLAG)  )
                continue; /* should not happen */

            if( poi->type == PORT_OBJECT_PORT  )
            {
              if( parray[poi->lport] )
                  cnt--;
              parray[poi->lport] =0;
            }

            else if( poi->type == PORT_OBJECT_RANGE )
            {
              int k;

              for(k=poi->lport;k<=poi->hport;k++)
              {
                 if( parray[k] )
                     cnt--;
                 parray[k] = 0;
              }
            }
        }
    }

    *nports = cnt;

    return parray;
}

/*
 *  Make a list of ports form the char array, each char is either
 *  on or off.
 */
static SF_LIST * PortObjectItemListFromCharPortArray( char * parray, int n )
{
   int i, lport ,hport;
   SF_LIST        * plist;
   PortObjectItem * poi;

   plist = sflist_new();
   if( !plist )
       return 0;

   for(i=0;i<n;i++)
   {
       if( parray[i] == 0 ) continue;

       /* Either a port or the start of a range */
       lport = hport = i;

       for(i++;i<n;i++)
       {
           if( parray[i] )
           {
               hport = i;
               continue;
           }
           break;
      }

      poi = PortObjectItemNew();
      if( !poi )
      {
          sflist_free_all(plist,free);
          return 0;
      }

      if( hport == lport )
      {
          poi->type = PORT_OBJECT_PORT;
          poi->lport = (unsigned short)lport;
      }
      else
      {
          poi->type = PORT_OBJECT_RANGE;
          poi->lport =(unsigned short)lport;
          poi->hport =(unsigned short)hport;
      }

      if( sflist_add_tail( plist, poi ) )
      {
          sflist_free_all( plist, free );
          return 0;
      }
   }

   return plist;
}

/*
 *  Removes Ports in B from A ... A = A - B
 */
int PortObjectRemovePorts( PortObject * a,  PortObject * b )
{
    int i;
    int nportsa;
    int nportsb;
    SF_LIST * plist;

    std::unique_ptr<char[]> upA(new char[SFPO_MAX_PORTS]);
    std::unique_ptr<char[]> upB(new char[SFPO_MAX_PORTS]);

    char* pA = upA.get();
    char* pB = upB.get();

    memset(pA,0,SFPO_MAX_PORTS);
    memset(pB,0,SFPO_MAX_PORTS);

    /* Create a char array of ports */
    PortObjectCharPortArray ( pA, a, &nportsa );

    /* Create a char array of ports */
    PortObjectCharPortArray ( pB, b, &nportsb );

    for(i=0;i<SFPO_MAX_PORTS;i++)
    {
       if( pB[i] ) pA[i] = 0; /* remove portB from A */
    }

    /* Convert the array into a Port Object list */
    plist = PortObjectItemListFromCharPortArray( pA, SFPO_MAX_PORTS );

    /* Release the old port list */
    sflist_free_all( a->item_list, free );

    /* Replace the old PortObject list */
    a->item_list = plist;

    return 0;
}

/*
 *   Normalize a port object
 *
 *   The reduces multiple references to a given port to a single unique reference
 *   This function should be used on each PortObject, once it's completed. After
 *   the normalized PortObject is created, the input PortObject may be deleted.
 */
int  PortObjectNormalize (PortObject * po )
{
    SF_LIST * plist;
    int nports = 0;

     if( PortObjectHasAny ( po ) )
     {
         return  0; /* ANY =65K */
     }

    std::unique_ptr<char[]> upA(new char[SFPO_MAX_PORTS]);
    char* parray = upA.get();

     memset(parray,0,SFPO_MAX_PORTS);

     /* Create a char array of ports */
     PortObjectCharPortArray ( parray, po, &nports );

     /* Convert the array into a Port Object list */
     plist = PortObjectItemListFromCharPortArray( parray, SFPO_MAX_PORTS );
     if( !plist )
         return -1;

     /* Release the old port list */
     sflist_free_all( po->item_list, free );

     /* Replace the old PortObject list */
     po->item_list = plist;

     return nports;
}

/*
*    Negate an entire PortObject
*/
int  PortObjectNegate (PortObject * po )
{
    int i;
    SF_LIST * plist;
    int nports = 0;

    if( PortObjectHasAny ( po ) )
    {
        return  0; /* ANY =65K */
    }

    std::unique_ptr<char[]> upA(new char[SFPO_MAX_PORTS]);
    char* parray = upA.get();

     memset(parray,0,SFPO_MAX_PORTS);

     /* Create a char array of ports */
     PortObjectCharPortArray ( parray, po, &nports );

     for(i=0;i<SFPO_MAX_PORTS;i++)
     {
         if(  parray[i] ) /* negate */
              parray[i] = 0;
         else
              parray[i] = 1;
     }

     /* Convert the array into a Port Object list */
     plist = PortObjectItemListFromCharPortArray( parray, SFPO_MAX_PORTS );

     /* Release the old port list */
     sflist_free_all( po->item_list, free );

     /* Replace the old PortObject list */
     po->item_list = plist;

     return nports;
}


/*
   PortObjects should be normalized, prior to testing
*/
static int PortObjectItemsEqual(PortObjectItem * a, PortObjectItem * b )
{
    if( a->type != b->type )
        return 0;

    switch( a->type )
    {
        case PORT_OBJECT_ANY:
            return 1;
        case PORT_OBJECT_PORT:
            if( a->lport == b->lport )
                return 1;
            break;
        case PORT_OBJECT_RANGE:
            if( a->lport == b->lport && a->hport == b->hport )
                return 1;
            break;
    }

    return 0;
}

/*
   PortObjects should be normalized, prior to testing
*/
int PortObjectEqual( PortObject * a, PortObject *b )
{
    PortObjectItem *pa;
    PortObjectItem *pb;
    SF_LNODE * posa;
    SF_LNODE * posb;

    if( a->item_list->count != b->item_list->count )
        return 0;

    pa = (PortObjectItem*)sflist_first(a->item_list,&posa);
    pb = (PortObjectItem*)sflist_first(b->item_list,&posb);

    while( pa && pb )
    {
      if( !PortObjectItemsEqual( pa, pb) )
          return 0;

      pa = (PortObjectItem*)sflist_next(&posa);
      pb = (PortObjectItem*)sflist_next(&posb);
    }

    if( pa || pb ) /* both are not done - cannot match */
        return 0;

    return 1; /* match */
}

/*
   Dup and Append PortObjectItems from pob to poa
*/
PortObject * PortObjectAppend(PortObject * poa, PortObject * pob )
{
   PortObjectItem * poia;
   PortObjectItem * poib;
   SF_LNODE* cursor;

   for( poib = (PortObjectItem*) sflist_first(pob->item_list, &cursor);
        poib!= 0;
        poib = (PortObjectItem*)sflist_next(&cursor) )
   {
       poia = PortObjectItemNew();

       if(!poia)
           return 0;

       memcpy(poia,poib,sizeof(PortObjectItem));

       sflist_add_tail(poa->item_list,poia);
   }
   return poa;
}
/* Dup and append rule list numbers from pob to poa */
PortObject * PortObjectAppendPortObject(PortObject * poa, PortObject * pob )
{
   int * prid;
   int * prid2;
   SF_LNODE * lpos;

   for( prid = (int*) sflist_first(pob->rule_list,&lpos);
        prid!= 0;
        prid = (int*)sflist_next(&lpos) )
   {
       prid2 = (int*)calloc( 1, sizeof(int));
       if( !prid2 )
           return 0;
       *prid2 = *prid;
       sflist_add_tail(poa->rule_list,prid2);
   }
   return poa;
}
/* Dup and append rule list numbers from pob to poa */
PortObject2 * PortObject2AppendPortObject(PortObject2 * poa, PortObject * pob )
{
   int * prid;
   int * prid2;
   SF_LNODE * lpos;

   for( prid = (int*) sflist_first(pob->rule_list,&lpos);
        prid!= 0;
        prid = (int*)sflist_next(&lpos) )
   {
       prid2 = (int*)calloc( 1, sizeof(int));
       if( !prid2 )
           return 0;
       *prid2 = *prid;
       if( sfghash_add(poa->rule_hash,prid2,prid2) != SFGHASH_OK )
       {
           free(prid2);
       }
   }
   return poa;
}
/* Dup and append rule list numbers from pob to poa */
PortObject2 * PortObject2AppendPortObject2(PortObject2 * poa, PortObject2 * pob )
{
   int * prid;
   int * prid2;
   SFGHASH_NODE * node;

   for( node = sfghash_findfirst(pob->rule_hash);
        node!= NULL;
        node = sfghash_findnext(pob->rule_hash) )
   {
       prid = (int*)node->data;
       if( !prid )
          continue;

       prid2 = (int*)calloc( 1, sizeof(int));
       if( !prid2 )
           return 0;

       *prid2 = *prid;
       if( sfghash_add(poa->rule_hash,prid2,prid2) != SFGHASH_OK )
       {
         free( prid2 );
       }
   }
   return poa;
}
/*
 *  Append Ports and Rules from pob to poa
 */
PortObject * PortObjectAppendEx(PortObject * poa, PortObject * pob )
{
   // LogMessage("PortObjectAppendEx: appending ports\n");
   if( !PortObjectAppend( poa, pob ) ) return 0;

   //LogMessage("PortObjectAppendEx: appending rules\n");
   if( !PortObjectAppendPortObject( poa, pob ) ) return 0;

   return poa;
}
/*
 *  Append Ports and Rules from pob to poa
 */
PortObject2 * PortObjectAppendEx2(PortObject2 * poa, PortObject * pob )
{
   // LogMessage("PortObjectAppendEx: appending ports\n");
   if( !PortObjectAppend((PortObject*) poa, pob ) ) return 0;

  //  LogMessage("PortObjectAppendEx: appending rules\n");
   if( !PortObject2AppendPortObject( poa, pob ) ) return 0;

   return poa;
}

/*
    PORT TABLE FUNCTIONS
*/

/*
    Create a new table
*/
PortTable * PortTableNew(void)
{
    PortTable *  p;

    p = (PortTable*) calloc(1,sizeof(PortTable));
    if(!p)
        return 0;

    p->pt_polist = sflist_new();
    if(!p->pt_polist )
    {
        free(p);
        return 0;
    }

    p->pt_lrc      =  PTBL_LRC_DEFAULT; /* 10 rules, user should really control these */
    p->pt_optimize =  1; /* if disabled, only one merged rule group is used */

    return p;
}

void PortTableFree(PortTable *p)
{
    int i;
    SFGHASH_NODE *node;

    if (!p)
        return;

    if (p->pt_polist)
    {
        sflist_free_all(p->pt_polist, PortObjectFree );
    }
    if (p->pt_mpo_hash)
    {
        PortObject2 *po;
        for (node = sfghash_findfirst(p->pt_mpo_hash);
             node;
             node = sfghash_findnext(p->pt_mpo_hash))
        {
            po = (PortObject2*)node->data;
            /* Free the data from this entry */
            PortObject2Free(po);
        }
        sfghash_delete(p->pt_mpo_hash);
    }
    if (p->pt_plx_list)
    {
        sflist_free_all(p->pt_plx_list, plx_free);
    }
    if (p->pt_mpxo_hash)
    {
#if 0
        PortObject2 *po;
        for (node = sfghash_findfirst(p->pt_mpxo_hash);
             node;
             node = sfghash_findnext(p->pt_mpxo_hash))
        {
            po = node->data;
            /* Free the data from this entry */
            //PortObject2Free(po);
        }
#endif
        sfghash_delete(p->pt_mpxo_hash);
    }
    for (i=0;i<SFPO_MAX_PORTS;i++)
    {
#if 0
        if (p->pt_port_object[i])
        {
            PortObject2Free(p->pt_port_object[i]);
        }
#endif
    }

    free(p);
}

PortObject * PortTableFindInputPortObjectName(PortTable * pt, char * po_name)
{
    SF_LNODE  * lpos;
    PortObject * po;

    if( !pt ) return NULL;
    if( !po_name ) return NULL;

    /* Normalize each of the input port objects */
    for(po =(PortObject*)sflist_first(pt->pt_polist,&lpos);
        po!=0;
        po =(PortObject*)sflist_next(&lpos) )
    {
        if( po->name )
        {
            if( strcmp(po->name,po_name)==0 )
            {
                return po;
            }
        }
    }
    return NULL;
}

/*
 * Find PortObject by PortItem Info
 */
PortObject * PortTableFindInputPortObjectPorts( PortTable * pt, PortObject * pox )
{
    SF_LNODE  * lpos;
    PortObject * po;

    if( !pt ) return NULL;
    if( !pox ) return NULL;

    for(po =(PortObject*)sflist_first(pt->pt_polist,&lpos);
        po!=0;
        po =(PortObject*)sflist_next(&lpos) )
    {
        if( PortObjectEqual( po, pox ) )
        {
            return po;
        }
    }
    return NULL;
}


int PortTableNormalizeInputPortObjects( PortTable *p )
{
    SF_LNODE  * lpos;
    PortObject * po;

    /* Normalize each of the input port objects */
    for(po =(PortObject*)sflist_first(p->pt_polist,&lpos);
        po!=0;
        po =(PortObject*)sflist_next(&lpos) )
    {
        PortObjectNormalize(po);
    }
 return 0;
}

int PortObjectAddRule( PortObject * po , int rule )
{
    int * pruleid;

    //LogMessage("Adding Rule %d to Port Object '%s'\n",rule,po->name);
    if( !po )
        return -1;

    if( !po->rule_list )
        return -1;

    /* Add rule index to rule list */
    pruleid = (int*)calloc(1,sizeof(int));
    if( !pruleid )
    {
      return -1;
    }

    *pruleid = rule;

    sflist_add_tail( po->rule_list, pruleid );

    return 0;
}

/*
    Add Users PortObjects to the Table

    We save the users port object, so it's no longer the users.
*/
int PortTableAddObject( PortTable *p, PortObject * po )
{
    SF_LNODE   * lpos;
    PortObject * pox;


    /* Search for the Port Object in the input list, by address */
    for(pox =(PortObject*)sflist_first(p->pt_polist,&lpos);
        pox!=0;
        pox =(PortObject*)sflist_next(&lpos) )
    {
        if( pox == po )
        {
            /* already in list - just return */
            return 0;
        }
    }

    /* Save the users port object, if not already in the list */
    if( sflist_add_tail(p->pt_polist,po) )
        return -1;

    return 0;
}



/*
    Hash routine for hashing PortObjects as Keys

    p - SFHASHFCN *
    d - PortObject *
    n = 4 bytes (sizeof*) - not used

   Don't use this for type=ANY port objects
*/
static unsigned PortObject_hash( SFHASHFCN * p, unsigned char *d, int )
{
    unsigned hash = p->seed;
    PortObjectItem * poi;
    PortObject     * po;
    SF_LNODE       * pos;

    po = *(PortObject**) d;

    /* hash up each item */
    for(poi =(PortObjectItem*)sflist_first(po->item_list,&pos);
        poi != NULL;
        poi =(PortObjectItem*)sflist_next(&pos) )
    {
       switch(poi->type)
       {
       case PORT_OBJECT_PORT:
           hash *=  p->scale;
           hash +=  poi->lport & 0xff;
           hash *=  p->scale;
           hash +=  (poi->lport >> 8) & 0xff;
           break;

       case PORT_OBJECT_RANGE:
           hash *=  p->scale;
           hash +=  poi->lport & 0xff;
           hash *=  p->scale;
           hash +=  (poi->lport >> 8) & 0xff;

           hash *=  p->scale;
           hash +=  poi->hport & 0xff;
           hash *=  p->scale;
           hash +=  (poi->hport >> 8) & 0xff;
           break;
       }
    }
    return hash ^ p->hardener;
}

/*
 * Merge multiple PortObjects into a final PortObject2,
 * this merges ports and rules.
 *
 *  merge po's in pol, find a previous instance add it.
 *
 *  This is done as follows:
 *  1) check if it's in the plx table-mhashx, this uses the list of
 *  addresses of the Input PortObjects as it's key, not the ports.
 *  This is quick and does not require assembling/merging the port
 *  objects intoa PortObject2 1st.
 *  2) if found were done, otherwise
 *  3) make a merged PortObject2
 *  4) Try adding the PortObject2 to it's table - mhash
 *     a) if it adds go on, else
 *     b) if it's already in the table
 *        1) get the one in the table
 *        2) add any ports in the just created one
 *        3) free the one just created
 *  5) Create a plx object
 *  6) Add the plx object to the plx Table
 *      1) if it's already in the object - fail this contradicts 1)
 *  7) return the create PortObject2, or the one retrived from the
 *     PortObject table.
 *
 * pol    - list of input PortObject pointers
 * pol_cnt- count in 'pol'
 * mhash  - stores the merged ports, using the merged port objects port list as a key.
 * mhashx - stores plx keys, and PortObject2 *'s as data for the final merged port objects,
 *          the plx keys provide a quicker way to compare port lists to ensure if two ports
 *          are using the same set of rules (port objects).
 * mhash and mhashx reference the same port objects as data, but use different keys for lookup
 * purposes. Once we perform a merge we store the results, using the 'plx' as the key for future lookup.
 * plx    - key to use to lookup and store the merged port object
 *
 *
 */
static PortObject2 * _merge_N_pol(
    SFGHASH * mhash, SFGHASH * mhashx,
    SF_LIST * plx_list, void ** pol,
    int pol_cnt, plx_t * plx )
{
    PortObject2 * ponew;
    PortObject2 * pox;
    plx_t       * plx_tmp;
    int           stat;
    int           i;

    /*
    * Check for the merged port object in the plx table
    */
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                            "++++n=%d sfghash_find-mhashx\n",pol_cnt););
    ponew = (PortObject2*)sfghash_find( mhashx, &plx );
    if( ponew )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                               "n=%d ponew found in mhashx\n",pol_cnt););
        return ponew;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                            "n=%d posnew not found in mhashx\n",pol_cnt););

    /*
    *  Merge the port objects together - ports and rules
    */


    /* Dup the 1st port objects rules and ports */
    ponew = PortObject2Dup( (PortObject *)pol[0] );
    if( !ponew )
    {
        FatalError("Could not Dup2\n");
    }

    /* Merge in all the other port object rules and ports */
    if( pol_cnt > 1 )
    {
        for(i=1;i<pol_cnt;i++)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"*** %d rules in object %d\n",
                                ((PortObject *)pol[i])->rule_list->count,i););
            PortObjectAppendEx2( ponew, (PortObject *)pol[i] );
            DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                   "*** merged port-object[%d], %d rules\n",
                   i,ponew->rule_hash->count););
        }
        PortObjectNormalize( (PortObject*)ponew );
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                    "*** merged %d port objects, %d rules\n",
                    pol_cnt,ponew->rule_hash->count););
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"*** merged ponew - follows: \n"););
    // PortObjectPrint2(ponew);

    /*
    * Add the Merged PortObject2 to the PortObject2 hash table
    * keyed by ports.
    */
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"n=%d sfghash_add-mhash\n",pol_cnt););
    stat =sfghash_add( mhash, &ponew, ponew );
    if( stat != SFGHASH_OK )
    {
        /* This is possible since PLX hash on a different key */
        if( stat == SFGHASH_INTABLE )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"n=%d sfghash_add-mhash ponew in table\n",pol_cnt););
            DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"n=%d sfghash_find-mhash ponew\n",pol_cnt););
            pox = (PortObject2*)sfghash_find(mhash,&ponew);
            if( pox )
            {
                PortObject2AppendPortObject2(pox,ponew);
                DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"sfportobject.c: merge_N_pol() line=%d  SFGHASH_INTABLE\n",__LINE__););
                PortObject2Free( ponew );
                ponew = pox;
                DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"n=%d sfghash_find-mhash ponew found, new rules merged\n",pol_cnt););
            }
            else
            {
                FatalError("mhash add/find error n=%d\n", pol_cnt);
            }
        }
        else
        {
            FatalError("Could not add ponew to hash table- error\n");
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"***%d ports merged object added to mhash  table\n",pol_cnt););

    /*
    * Create a plx node and add it to plx table
    * as the key with the merged port object as the data
    */
    plx_tmp = plx_new( pol, pol_cnt);
    if(!plx_tmp)
    {
        FatalError("plx_new: memory alloc error\n");
    }
    sflist_add_head(plx_list, (void *)plx_tmp);

    /*
     * Add the plx node to the PLX hash table
     */
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"n=%d sfghash_add-mhashx\n",pol_cnt););
    stat = sfghash_add( mhashx, &plx_tmp, ponew );
    if( stat != SFGHASH_OK )
    {
        if( stat == SFGHASH_INTABLE )
        {
            FatalError("Could not add merged plx to PLX HASH table-INTABLE\n");
        }
        else
        {
            FatalError("Could not add merged plx to PLX HASH table\n");
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"Added-%d Merged Rule Groups to PLX HASH\n",pol_cnt););

    /*
    *  Validate hash table entry
    */
    if( sfghash_find( mhashx, &plx_tmp ) != ponew )
    {
        FatalError("Find after add failed on PLX HASH table key\n");
    }

    return ponew;
}
/*
 * Merge Input Port Objects into rule collections that are particular to
 * each port.  We store the results as objects and point to these in the
 * pt_port_object[MAX_PORTS] array.
 *
 * We use plx_t types to manage tracking and testing for merged large
 * rule groups, and merged small port groups.
 *
 * mhash   - table of merged port objects ( built and used here )
 * mhashx  - table of plx_t objects ( built and used here )
 * pol     - list of input port objects touching the current port
 * pol_cnt - number of port objects in port list
 * lcnt    - large rule count
 *
 */
static PortObject2 * PortTableCompileMergePortObjectList2(
    SFGHASH* mhash, SFGHASH* mhashx, SF_LIST* plx_list,
    PortObject* pol[], int pol_cnt, unsigned int lcnt )
{
    PortObject2 * ponew = NULL;
    PortObject2 * posnew = NULL;
    int nlarge = 0;
    int nsmall = 0;
    plx_t plx_small;
    plx_t plx_large;
    unsigned largest;
    int i;

    std::unique_ptr<void*[]> upA(new void*[SFPO_MAX_LPORTS]);
    std::unique_ptr<void*[]> upB(new void*[SFPO_MAX_LPORTS]);

    void** polarge = upA.get();
    void** posmall = upB.get();

    /*
    * Find the largest rule count of all of the port objects
    */
    largest = 0;
    for(i=0;i<pol_cnt;i++)
    {
      if( pol[i]->rule_list->count >= (unsigned)lcnt )
      {
        if( pol[i]->rule_list->count > largest )
          largest =  pol[i]->rule_list->count;
      }
    }

    /*
    * Classify PortObjects as large or small based on rule set size
    * and copy them into separate lists
    */
    for(i=0;i<pol_cnt;i++)
    {
      if( pol[i]->rule_list->count >= (unsigned)lcnt )
      {
         if( nlarge < SFPO_MAX_LPORTS )
             polarge[ nlarge++ ] = (void *)pol[i];
      }
      else
      {
         if( nsmall < SFPO_MAX_LPORTS )
             posmall[ nsmall++ ] = (void *)pol[i];
      }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"*** %d small rule groups, %d large rule groups\n",nsmall,nlarge););

    /*
    * Sort the pointers to the input port objects so
    * we always get them in the same order for key comparisons
    */
    if( nlarge > 1 )
        qsort( polarge, nlarge, sizeof(void*), p_keycmp );
    if( nsmall > 1 )
        qsort( posmall, nsmall, sizeof(void*), p_keycmp );

    DEBUG_WRAP(
        for(i=0;i<nsmall;i++) DebugMessage(DEBUG_PORTLISTS, "posmall[%d]=%lu\n",i,posmall[i]);
        for(i=0;i<nlarge;i++) DebugMessage(DEBUG_PORTLISTS, "polarge[%d]=%lu\n",i,polarge[i]);
    );

    /*
    * Setup plx_t representation of port list pointers
    */
    plx_small.n = nsmall;
    plx_small.p = (void**)&posmall[0];

    plx_large.n = nlarge;
    plx_large.p = (void**)&polarge[0];

#ifdef DEBUG_MSGS
    if( nlarge )
    {
        DebugMessage(DEBUG_PORTLISTS, "large "); plx_print(&plx_large);
    }
    if( nsmall )
    {
        DebugMessage(DEBUG_PORTLISTS, "small "); plx_print(&plx_small);
    }
#endif

    /*
    * Merge Large PortObjects
    */
    if( nlarge )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"***nlarge=%d \n",nlarge););
        ponew =  _merge_N_pol( mhash, mhashx, plx_list, polarge, nlarge, &plx_large);
    }

    /*
    * Merge Small PortObjects
    */
    if( nsmall )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"***nsmall=%d \n",nsmall););
        posnew =  _merge_N_pol( mhash, mhashx, plx_list, posmall, nsmall, &plx_small);
    }
    /*
    * Merge Large and Small (rule groups) PortObject2's together
    * append small port object rule sets to the large port objects,
    * remove the large port objects ports from the smaller port objects
    */
    if( nlarge && nsmall )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"*** appending small rules to larger rule group\n"););
        if (ponew != posnew)
        {

            /* Append small port object, just the rules */
            PortObject2AppendPortObject2( ponew, posnew );

            /* Remove Ports in ponew from posnew */
            PortObjectRemovePorts( (PortObject*)posnew, (PortObject*)ponew );
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"*** final - using small+large rule group \n"););
    }
    else if( nsmall )
    {
        /* Only a small port object */
        ponew = posnew;

        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"*** final - using small rule group only \n"););
    }
    else if( nlarge )
    {
        /*
         * The large rule group port object is already set to ponew
         */
    }

    return ponew;
}
/*
 *
 *
 * mhash
 * mhashx
        data structure used: p->pt_polist
 */
int PortTableCompileMergePortObjects( PortTable * p )
{
    SF_LNODE   * lpos;
    SFGHASH    * mhash;
    SFGHASH    * mhashx;
    SFGHASH_NODE * node;
    SF_LIST    * plx_list;
    int          id = PO_INIT_ID;
    int          pol_cnt;
    char  *      parray = NULL;
    int i;

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"***\n***Merging PortObjects->PortObjects2\n***\n"););

    std::unique_ptr<PortObject*[]> upA(new PortObject*[SFPO_MAX_LPORTS]);
    PortObject** pol = upA.get();

    /* Create a Merged Port Object Table  - hash by ports */
    mhash = sfghash_new(PO_HASH_TBL_ROWS, sizeof(PortObject *), 0 /*userkeys-no*/, 0 /*free data-don't*/);
    if( !mhash )
        return -1;

    /* Setup hashing function and key comparison function */
    sfhashfcn_set_keyops( mhash->sfhashfcn, PortObject_hash, PortObject_keycmp );

    /* remove randomness */
    if (ScStaticHash())
        sfhashfcn_static( mhash->sfhashfcn );

    p->pt_mpo_hash = mhash;

    /* Create a Merged Port Object Table  - hash by ports */
    mhashx = sfghash_new(PO_HASH_TBL_ROWS, sizeof(plx_t *), 0/*userkeys-no*/, 0/*freedata()-don't*/);
    if( !mhashx )
        return -1;
    /* Setup hashing function and key comparison function */
    sfhashfcn_set_keyops( mhashx->sfhashfcn,plx_hash,plx_keycmp );

    /* remove randomness */
    if (ScStaticHash())
        sfhashfcn_static( mhashx->sfhashfcn );

    p->pt_mpxo_hash = mhashx;

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"***\n*** PortList-Merging, Large Rule groups must have %d rules\n",p->pt_lrc););

    plx_list = sflist_new();
    sflist_init(plx_list);

    p->pt_plx_list = plx_list;

    /*
     *  For each port, merge rules from all port objects that touch the port
     *  into an optimal object, that may be shared with other ports.
     */
    for(i=0;i<SFPO_MAX_PORTS;i++)
    {
        PortObject * po;

        /* Build a list of port objects touching port 'i' */
        pol_cnt = 0;
        for(po=(PortObject*)sflist_first(p->pt_polist,&lpos);
            po;
            po=(PortObject*)sflist_next(&lpos) )
        {
            if( PortObjectHasPort ( po, i  ) )
            {
                if( pol_cnt < SFPO_MAX_LPORTS )
                {
                    pol[ pol_cnt++ ] = po;
                }
            }
        }
        p->pt_port_object[i] = 0;

        if( !pol_cnt )
        {
            //port not contained in any PortObject
            continue;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"*** merging list for port[%d] \n",i);fflush(stdout););

        /* merge the rules into an optimal port object */
        p->pt_port_object[i] =
            PortTableCompileMergePortObjectList2( mhash, mhashx, plx_list, pol, pol_cnt, p->pt_lrc );
        if( !p->pt_port_object[i] )
        {
            FatalError(" Could not merge PorObjectList on port %d\n",i);
        }

        /* give the new compiled port object an id of its own */
        p->pt_port_object[i]->id = id++;

        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"\n");fflush(stdout););
    }

    /*
     * Normalize the Ports so they indicate only the ports that
     * reference the composite port object
     */

    /* 1st- Setup bitmasks for collecting ports */
    for(node=sfghash_findfirst(mhashx);
        node;
        node=sfghash_findnext(mhashx) )
    {
        unsigned char * buf;
        PortObject2 * poa;

        poa = (PortObject2*)node->data;
        if( !poa )
            continue;

        if (!poa->bitop)
        {
            poa->bitop = (BITOP*)calloc(1,sizeof(BITOP));
            if( !poa->bitop)
            {
                FatalError("Memory error in PortTableCompile\n");
            }
            buf = (unsigned char*)calloc(1,8192);
            if( !buf )
            {
                FatalError("Memory alloc error in PortObjectCompile()\n");
            }
            if( boInitStaticBITOP(poa->bitop,8192,buf) )
            {
                FatalError("BitOp error in PortObjectCompile()\n");
            }
        }
    }

    /* Count how many ports each final port-object is used on */
    for(i=0;i<SFPO_MAX_PORTS;i++)
    {
        PortObject2 * poa;
        poa = p->pt_port_object[i];
        if(poa)
        {
            poa->port_cnt++;
            if( poa->bitop )
            {
                if( boSetBit(poa->bitop, (unsigned int) i ) )
                {
                    FatalError("BitOp-Set error\n");
                }
            }
            else
            {
                FatalError("NULL po->bitop in po on port %d\n",i);
            }
        }
    }

    /* get a port array 64K bytes */
    parray = (char*)calloc(1,SFPO_MAX_PORTS);
    if(!parray)
    {
        FatalError("Memory error in PortTableCompile()\n");
    }

    /* Process Port-Bitop map and print final port-object usage stats */
    for(node=sfghash_findfirst(mhashx);
        node;
        node=sfghash_findnext(mhashx) )
    {
        SF_LIST     * plist;
        PortObject2 * po;

        po = (PortObject2*)node->data;
        if( !po )
        {
            FatalError("MergePortOBject-NormalizePorts -NULL po\n");
        }

        if( !po->port_cnt )/* port object is not used ignore it */
            continue;

        if( !po->bitop )
        {
            //FatalError("MergePortOBject-NormalizePorts -NULL po->bitop\n");
            continue;
        }

        /* Convert the bitop bits to a char array */
        memset(parray,0,SFPO_MAX_PORTS);
        for(i=0;i<SFPO_MAX_PORTS;i++)
        {
          if(  boIsBitSet(po->bitop, i ) )
          {
             parray[ i ] = 1;
          }
        }

        /* Release bit buffer for each port object */
        if( po->bitop )
        {
            //if( po->bitop->pucBitBuffer )
            //{
            //    free( po->bitop->pucBitBuffer );
            //    po->bitop->pucBitBuffer = NULL;
            //}
            boFreeBITOP(po->bitop);
            free( po->bitop );
            po->bitop=NULL;
        }

        /* Build a PortObjectItem list from the char array */
        plist = PortObjectItemListFromCharPortArray( parray, SFPO_MAX_PORTS );
        if( !plist )
        {
           FatalError("MergePortObjects: No PortObjectItems in portobject\n");
        }

        /* free the original list */
        sflist_free_all( po->item_list, free );

        /* set the new list - this is a list of port itmes for this port object */
        po->item_list = plist;

        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"port-object id = %d, port cnt = %d\n",po->id,po->port_cnt););
    }

    if(parray) free(parray);

    return 0;
}
/*
 *
 *  Verify all rules in 'po' list are in 'po2' hash
 *
 *  return  0 - OK
 *         !0 - a rule in po is not in po2
 */
static int _po2_include_po_rules( PortObject2 * po2, PortObject * po  )
{
    //SFGHASH_NODE * node;
    int * pid;
    int * id;
    SF_LNODE * rpos;

    /* get each rule in po */
    for(pid=(int*)sflist_first(po->rule_list,&rpos);
        pid;
        pid=(int*)sflist_next(&rpos) )
    {
       /* find it in po2 */
       id =(int*) sfghash_find(po2->rule_hash,pid);

       /* make sure it's in po2 */
       if(!id )
       {
          return 1; /* error */
       }
    }

    return 0;
}

/*
 * Perform a consistency check on the final port+rule objects
 *
 * Walk the rules
 */
int PortTableConsistencyCheck( PortTable *p )
{
    SFGHASH_NODE * node;
    int i;
    SF_LNODE * pos;
    SF_LNODE * ipos;
    PortObject * ipo;
    PortObject2 * lastpo = NULL;
    PortObjectItem * poi;

    std::unique_ptr<char[]> upA(new char[SFPO_MAX_PORTS]);
    char* parray = upA.get();
    memset(parray,0,SFPO_MAX_PORTS);

    /*  Make sure each port is only in one composite port object */
    for(node=sfghash_findfirst(p->pt_mpo_hash);
        node;
        node=sfghash_findnext(p->pt_mpo_hash) )
    {
        PortObject2 * po;
        po = (PortObject2*)node->data;

        if( !po )
        {
          FatalError("PortObject consistency Check failed, hash table problem\n");
        }

        if( !po->port_cnt )/* port object is not used ignore it */
              continue;

        for(i=0;i<SFPO_MAX_PORTS;i++)
        {
           if( PortObjectHasPort( (PortObject*)po, i  ) )
           {
              if( parray[i] )
              {
                 FatalError("PortTableCompile: failed consistency check, multiple objects reference port %d\n",i);
              }
              parray[i]=1;
           }
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"***\n***Port Table Compiler Consistency Check Phase-I Passed !\n"););


    /*
    * This phase checks the Input port object rules/ports against
    * the composite port objects.
    *
    * For each input object
    *    check that each port it reference has all of the rules
    *    referenced to that port in the composit object
    */
    for(ipo=(PortObject*)sflist_first(p->pt_polist,&pos);
        ipo;
        ipo=(PortObject*)sflist_next(&pos) )
    {
        /*
         * for each port in this object get the composite port object
         * assigned to that port and verify all of the input objects rules
         * are in the composite object.  This verifies all rules are applied
         * to the originally intended port.
         */
        for(poi=(PortObjectItem*)sflist_first(ipo->item_list,&ipos);
            poi;
            poi=(PortObjectItem*)sflist_next(&ipos) )
        {
            switch(poi->type)
            {
                case PORT_OBJECT_ANY: /* do nothing */
                break;

                case PORT_OBJECT_PORT:
                if( _po2_include_po_rules( p->pt_port_object[ poi->lport ], ipo  ) )
                {
                    FatalError("InputPortObject<->CompositePortObject consistency Check II failed!\n");
                }
                break;

                case PORT_OBJECT_RANGE:
                {
                    for(i=poi->lport;i<=poi->hport;i++)
                    {
                        /* small optimization*/
                        if( lastpo != p->pt_port_object[ i ] )
                        {
                            if( _po2_include_po_rules( p->pt_port_object[ i ], ipo  ) )
                            {
                                FatalError("InputPortObject<->CompositePortObject consistency Check II failed!\n");
                            }
                            lastpo = p->pt_port_object[ i ];
                        }
                    }
                }
                break;
            }
        }
    }

   DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
              "***\n***Port Table Compiler Consistency Check Phase-II Passed !!! - Good to go Houston\n****\n"););
   return 0;
}

/*
* Compile the PortTable
*
* This builds a set of Port+Rule objects that are in some way an optimal
* set of objects to indicate which rules to apply to which ports. Since
* these groups are calculated consistency checking is done witht he finished
* objects.
*/
int PortTableCompile( PortTable * p )
{
    /*
    *  If not using an optimized Table use the rule_index_map in parser.c
    */
    if( !p->pt_optimize )
    {
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"#PortTableCompile: Compiling Port Array Lists\n"););

    if( PortTableCompileMergePortObjects( p ) )
    {
        FatalError("Could not create PortArryayLists\n");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"Done\n");fflush(stdout););

    PortTableConsistencyCheck(p);

    return 0;
}
static int integer_compare( const void *arg1, const void *arg2 )
{
   if( *(int*)arg1 <  *(int*)arg2 ) return -1;
   if( *(int*)arg1 >  *(int*)arg2 ) return  1;
   return  0;
}

static int * RuleListToSortedArray( SF_LIST * rl )
{
    SF_LNODE       * pos = NULL;
    int          * prid;
    int          * ra;
    int            k=0;

    if( !rl )
        return 0;

    if(!rl->count)
        return NULL;

    ra = (int *)SnortAlloc(rl->count * sizeof(int));

    for( prid = (int*)sflist_first(rl,&pos);
         prid!= 0 && k < (int)rl->count;
         prid = (int*)sflist_next(&pos) )
    {
        ra[k++] = *prid;
    }

    /* sort the array */
    qsort(ra,rl->count,sizeof(int),integer_compare);

    return ra;
}
/**sort and uniq rule list.
 */
void RuleListSortUniq(
        SF_LIST * rl
        )
{
    unsigned i;
    int lastRuleIndex = -1;
    SF_LNODE *pos = NULL;
    int *currNode = NULL;
    unsigned uniqElements = 0;
    int *node = 0;
    int * rlist = NULL;

    rlist = RuleListToSortedArray(rl);
    if(!rlist )
    {
        return ;
    }

    currNode = (int*)sflist_first(rl,&pos);
    if (currNode == NULL)
        return;

    for(i=0; i < rl->count; i++)
    {
        if (rlist[i] > lastRuleIndex)
        {
            *currNode = lastRuleIndex = rlist[i];
            //replace the next element in place
            currNode = (int*)sflist_next(&pos);
            uniqElements++;
        }
    }

    //free the remaining list nodes
    while (uniqElements != rl->count)
    {
         node = (int*)sflist_remove_tail (rl);
         free(node);
    }

    free(rlist);
}

/**Sort and make rule index in all port objects unique. Multiple policies may add
 * the same rule which can lead to duplication.
 */
void PortTableSortUniqRules(
        PortTable * p
        )
{
    PortObject * po;
    SF_LNODE   *pos = NULL;

    for(po =(PortObject*)sflist_first(p->pt_polist,&pos);
        po != NULL;
        po =(PortObject*)sflist_next(&pos) )
    {
        RuleListSortUniq(po->rule_list);
    }
}

static int * RuleHashToSortedArray( SFGHASH * rh )
{
    int          * prid;
    int          * ra;
    int            k = 0;
    SFGHASH_NODE * node;

    if( !rh )
        return 0;

    if(!rh->count)
        return NULL;

    ra = (int *)SnortAlloc(rh->count * sizeof(int));

    for( node = sfghash_findfirst(rh);
         node != 0 && k < (int)rh->count;
         node = sfghash_findnext(rh) )
    {
        prid = (int*)node->data;
        if( prid )
        {
            ra[k++] = *prid;
        }
    }

    /* sort the array */
    qsort(ra,rh->count,sizeof(int),integer_compare);

    return ra;
}

/*
 *  Print Input Port List
 */
void PortTablePrintInput( PortTable * p )
{
    PortObject * po;
    SF_LNODE   * pos;

    LogMessage("*** %d PortObjects in Table\n",p->pt_polist->count);
    for(po =(PortObject*)sflist_first(p->pt_polist,&pos);
        po!=0;
        po =(PortObject*)sflist_next(&pos) )
    {
        PortObjectPrint( po );
    }
}

void PortTablePrintInputEx( PortTable * p,
        void (*print_index_map)(int index, char *buf, int bufsize) )
{
    PortObject * po;
    SF_LNODE   * pos;
    for(po =(PortObject*)sflist_first(p->pt_polist,&pos);
        po != NULL;
        po =(PortObject*)sflist_next(&pos) )
    {
        PortObjectPrintEx( po, print_index_map );
    }
}
/*
   Prints Compiled Ports/Rules Objects
*/
int PortTablePrintCompiledEx( PortTable * p ,
        void (*print_index_map)(int index, char *buf, int bufsize) )
{
    PortObject2  * po = NULL;
    SFGHASH_NODE * node = NULL;

    LogMessage(" *** PortTableCompiled  [ %d compiled port groups ] \n\n",
           p->pt_mpo_hash->count);

    for(node = sfghash_findfirst(p->pt_mpo_hash);
        node!= 0;
        node = sfghash_findnext(p->pt_mpo_hash) )
    {
        po = (PortObject2*)node->data;

        PortObject2PrintEx( po, print_index_map );
    }

    return 0;
}

/*
   Print port items.  Used internally by sfportobject.c.
   Buffer assumed trusted.
*/
static void PortObjectItemPrint ( PortObjectItem * poi, char *dstbuf, int bufsize )
{
    SnortSnprintfAppend(dstbuf, bufsize, " ");

    if( poi->flags & PORT_OBJECT_NOT_FLAG )
        SnortSnprintfAppend(dstbuf, bufsize, "!");

    switch( poi->type )
    {
        case PORT_OBJECT_PORT :
            SnortSnprintfAppend(dstbuf, bufsize, "%u", poi->lport);
        break;

        case PORT_OBJECT_RANGE :
            SnortSnprintfAppend(dstbuf, bufsize, "%u:%u",poi->lport,poi->hport);
        break;

        case PORT_OBJECT_ANY:
            SnortSnprintfAppend(dstbuf, bufsize, "any");
        break;

        default:
            SnortSnprintfAppend(dstbuf, bufsize, " unknown port type @ %p", (void*)poi);
        break;
    }
}

void PortObjectPrintPortsRaw(PortObject * po )
{
    PortObjectItem * poi = NULL;
    SF_LNODE       * pos = NULL;
    char           * buf;
    int              bufsize;

    /* Need to buffer the string so we only do one LogMessage,
     * due to syslog output.  The largest string needed to represent
     * each portobject is the length required to represent:
     * " unknown port type @ 0x<8 max bytes>" (See PortObjectItemPrint), or:
     * 30 bytes.  For the entire list, need room for spaces and brackets and
     * potential negations. Or:
     *      list_size * (30 + 1space_for_each_element, +
     *       1potential_negation) + surrounding_whitespace + brackets + NULL */

    bufsize = po->item_list->count * (30 + 1 + 1) + 5;
    buf = (char*)SnortAlloc(bufsize);

    SnortSnprintfAppend(buf, bufsize, " [");

    for(poi=(PortObjectItem*)sflist_first(po->item_list, &pos);
        poi != 0;
        poi=(PortObjectItem*)sflist_next(&pos) )
    {
        PortObjectItemPrint(poi, buf, bufsize);
    }

    SnortSnprintfAppend(buf, bufsize, " ]");

    LogMessage("%s", buf);

    free(buf);
}


void PortObject2PrintPorts(PortObject2 * po )
{
    PortObjectItem * poi = NULL;
    SF_LNODE       * pos = NULL;
    int              bufsize = sizeof(po_print_buf);

    po_print_buf[0] = '\0';

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject ");

    if( po->name )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "%s ", po->name);
    }

    SnortSnprintfAppend(po_print_buf, bufsize,
                 " Id:%d  Ports:%d Rules:%d\n {\n Ports [",
                 po->id, po->item_list->count, po->rule_hash->count);

    if( PortObjectHasAny( (PortObject*)po ) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
        for(poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != 0;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            PortObjectItemPrint(poi, po_print_buf, bufsize);
        }
    }

    SnortSnprintfAppend(po_print_buf, bufsize, " ]\n }\n");
    LogMessage("%s", po_print_buf);
}

/*
   Print Port Object - Prints input ports and rules (uncompiled)
    ports
    rules (input by user)

*/
void PortObjectPrintEx(PortObject * po,
                 void (*print_index_map)(int index, char *buf, int bufsize) )
{
    PortObjectItem * poi = NULL;
    SF_LNODE       * pos = NULL;
    int              k=0;
    int            * rlist = NULL;
    unsigned         i;
    int              bufsize = sizeof(po_print_buf);

    po_print_buf[0] = '\0';

    if( !po )
        return ;

    if( !po->rule_list )
        return ;

    if( !po->rule_list->count )
        return ;

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject ");

    if( po->name )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "%s ", po->name);
    }

    SnortSnprintfAppend(po_print_buf, bufsize,
            " Id:%d  Ports:%d Rules:%d\n {\n",
            po->id, po->item_list->count,po->rule_list->count );

    SnortSnprintfAppend(po_print_buf, bufsize, "  Ports [\n  ");

    if( PortObjectHasAny( po ) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
      for(poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
          poi != 0;
          poi=(PortObjectItem*)sflist_next(&pos) )
          {
             PortObjectItemPrint(poi, po_print_buf, bufsize);
          }
    }
    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n");

    rlist = RuleListToSortedArray( po->rule_list );
    if(!rlist )
    {
        return ;
    }

    SnortSnprintfAppend(po_print_buf, bufsize, "  Rules [ \n ");
    for(i=0;i<po->rule_list->count;i++)
    {
        if( print_index_map )
        {
          print_index_map( rlist[i], po_print_buf, bufsize );
        }
        else
        {
          SnortSnprintfAppend(po_print_buf, bufsize, " %d",rlist[i]);
        }
        k++;
        if( k == 25 )
        {
            k=0;
            SnortSnprintfAppend(po_print_buf, bufsize, " \n ");
        }
    }
    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n }\n");

    LogMessage("%s", po_print_buf);
    free(rlist);
}
void PortObjectPrint (PortObject * po )
{
    PortObjectPrintEx( po, rule_index_map_print_index );
}

void PortObject2PrintEx(PortObject2 * po,
            void (*print_index_map)(int index, char *buf, int bufsize) )
{
    PortObjectItem * poi = NULL;
    SF_LNODE       * pos = NULL;
    int              k=0;
    int            * rlist = NULL;
    unsigned int     i;
    int              bufsize = sizeof(po_print_buf);

    po_print_buf[0] = '\0';

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject2 ");

    if( po->name ) SnortSnprintfAppend(po_print_buf, bufsize, "%s ",po->name);

    SnortSnprintfAppend(po_print_buf, bufsize, " Id:%d  Ports:%d Rules:%d PortUsageCnt=%d\n {\n",
            po->id, po->item_list->count, po->rule_hash->count, po->port_cnt );

    SnortSnprintfAppend(po_print_buf, bufsize, "  Ports [\n  ");

    if( PortObjectHasAny( (PortObject*)po ) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
        for(poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != 0;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            PortObjectItemPrint(poi, po_print_buf, bufsize);
        }
    }

    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n");

    rlist = RuleHashToSortedArray( po->rule_hash );
    if(!rlist )
        return ;

    SnortSnprintfAppend(po_print_buf, bufsize, "  Rules [ \n ");
    for(i=0;i<po->rule_hash->count;i++)
    {
        if( print_index_map )
        {
            print_index_map( rlist[i], po_print_buf, bufsize );
        }
        else
        {
            SnortSnprintfAppend(po_print_buf, bufsize, " %d", rlist[i]);
        }
        k++;
        if( k == 25 )
        {
            k=0;
            SnortSnprintfAppend(po_print_buf, bufsize, " \n ");
        }
    }
    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n }\n");

    LogMessage("%s", po_print_buf);

    free(rlist);
}
void PortObject2Print (PortObject2 * po )
{
    PortObject2PrintEx( po, rule_index_map_print_index );
}
/*
   Prints the original (normalized) PortGroups and
   as sepcified by the user
*/
void PortTablePrintUserRules( PortTable * p )
{
    PortObject * po;
    SF_LNODE* cursor;

    /* normalized user PortObjects and rule ids */
    LogMessage(">>>PortTable - Rules\n");
    for(po = (PortObject*)sflist_first(p->pt_polist, &cursor);
        po!= 0;
        po = (PortObject*)sflist_next(&cursor) )
    {
        PortObjectPrint( po );
    }
    /* port array of rule ids */
}

/*
    Prints the Unique Port Groups and rules that reference them
*/
void PortTablePrintPortGroups( PortTable * p )
{
    PortObject2 * po;
    SFGHASH_NODE * ponode;

    /* normalized user PortObjects and rule ids */
    LogMessage(">>>PortTable - Compiled Port Groups\n");
    LogMessage("   [ %d port groups ] \n\n",p->pt_mpo_hash->count);

    for(ponode = sfghash_findfirst(p->pt_mpo_hash);
        ponode!= 0;
        ponode = sfghash_findnext(p->pt_mpo_hash) )
    {
        po = (PortObject2*)ponode->data;

        PortObject2Print(po);
    }
    /* port array of rule ids */
}

/*
   Print
*/
void PortTablePrintPortPortObjects( PortTable * p )
{
   int i;
   PortObject * po;
   SF_LIST    * last = NULL;
   int          bufsize = sizeof(po_print_buf);

   po_print_buf[0] = '\0';

   LogMessage(">>>Port PortObjects\n");

   for(i=0;i<SFPO_MAX_PORTS;i++)
   {
      if( !p->pt_port_lists[i] ) continue;

      if( p->pt_port_lists[i] == last )
          continue;

      SnortSnprintfAppend(po_print_buf, bufsize, "---Port[%d] PortObjects [ ",i);
      SF_LNODE* cursor;

      for(po=(PortObject*)sflist_first(p->pt_port_lists[i], &cursor);
          po != 0;
          po=(PortObject*)sflist_next(&cursor) )
          {
            SnortSnprintfAppend(po_print_buf, bufsize, "%d ",po->id);
          }

          SnortSnprintfAppend(po_print_buf, bufsize, "]\n");

          last = p->pt_port_lists[i] ;

   }

   LogMessage("%s", po_print_buf);
}


/*
*
*  Port Object Parser
*
*/

static int POParserInit( POParser * pop, const char * s, PortVarTable * pvTable )
{
   memset(pop,0,sizeof(POParser));
   pop->pos     = 0;
   pop->s       = s;
   pop->slen    = strlen(s);
   pop->errflag = 0;
   pop->pvTable = pvTable;

   return 0;
}

/*
    Get a Char
*/
static int POPGetChar( POParser * pop )
{
   int c;
   if( pop->slen > 0 )
   {
       c = pop->s[0];
       pop->slen--;
       pop->s++;
       pop->pos++;
       DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"GetChar: %c, %d bytes left\n",c, pop->slen););
       return c;
   }
   return 0;
}
/*
   Skip whitespace till we find a non-whitespace char
*/
static int POPGetChar2( POParser * pop )
{
   int c;
   for(;;)
   {
       c=POPGetChar( pop ) ;
       if( !c )
             return 0;

       if( isspace(c) || c==',' )
           continue;

       break;
   }
   return c;
}
/*
   Restore last char
*/
static void POPUnGetChar( POParser * pop )
{
   if( pop->pos > 0 )
   {
     pop->slen++;
     pop->s--;
     pop->pos--;
   }
}
/*
  Peek at next char
*/
static int POPPeekChar( POParser * pop )
{
   if( pop->slen > 0)
   {
       return  pop->s[0];
   }
   return 0;
}
#ifdef XXXX
/* copy a simple alpha string */
static void POPeekString(POParser * p, char * s, int smax)
{
    int c;
    int cnt = 0;
    int k = p->slen;

    smax--;

    s[0] = 0;

    while( k > 0  && cnt < smax )
    {
        c = p->s[ cnt ];

        if( c ==  0     ) break;
        if( !isalpha(c) ) break;

        s[ cnt++ ] = c;
        s[ cnt   ] = 0;
        k--;
    }
}
static void POGetString(POParser * p, char * s, int smax)
{
    int c;
    int cnt = 0;

    smax--;

    s[0] = 0;

    while( p->slen > 0  && cnt < smax )
    {
        c = p->s[ 0 ];

        if( c ==  0     ) break;
        if( !isalpha(c) ) break;

        s[ cnt++ ] = c;
        s[ cnt   ] = 0;
        p->slen--;
        p->s++;
    }
}
#endif

/*
   Skip whitespace : ' ', '\t', '\n'
*/
static int POPSkipSpace( POParser * p )
{
   int c;
   for( c  = POPPeekChar(p);
        c != 0 ;
        c  = POPPeekChar(p) )
   {
        if( !isspace(c) && c != ',' )
           return c;

        POPGetChar(p);
   }
   return 0;
}
/*
  Get the Port Object Name
*/
static char * POParserName( POParser * pop )
{
    int k = 0;
    int c;

    /* check if were done  */
    if( !pop || !pop->s || !*(pop->s) )
        return 0;

    /* Start the name - skip space */
    c = POPGetChar2(pop) ;
    if( !c )
        return 0;

    if( c== '$' )/* skip leading '$' - old Var indicator */
    {
        c = POPGetChar2(pop) ;
        if( !c )
            return 0;
    }

    if( isalnum(c) )
    {
        pop->token[k++] = (char)c;
        pop->token[k]   = (char)0;
    }
    else
    {
        POPUnGetChar( pop );
        return 0; /* not a name */
    }

    for( c  = POPGetChar(pop);
         c != 0 && k < POP_MAX_BUFFER_SIZE;
         c  = POPGetChar(pop) )
    {
        if( isalnum(c) || c== '_' || c=='-' || c=='.' )
        {
            pop->token[k++] = (char)c;
            pop->token[k]   = (char)0;
        }
        else
        {
            POPUnGetChar( pop );
            break;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,">>> POParserName : %s\n",pop->token););

    return strdup(pop->token);
}

/*
*   Read an unsigned short (a port)
*/
static uint16_t POParserGetShort(POParser * pop)
{
    int    c;
    int    k = 0;
    char   buffer[32];
    char * pend;


    POPSkipSpace(pop);

    buffer[0] = 0;

    while( (c = POPGetChar(pop)) != 0 )
    {
        if( isdigit(c) )
        {
            buffer[k++]=(char)c;
            buffer[k]  =0;
            if( k == sizeof(buffer)-1 ) break; /* thats all that fits */
        }
        else
        {
            if( c && ( c!= ':' && c != ' ' && c != ']' && c != ',' && c != '\t' && c != '\n' ) )
            {
                pop->errflag = POPERR_NOT_A_NUMBER;
                return 0;
            }
            POPUnGetChar(pop);
            break;
        }
    }

    c  = (int)strtoul(buffer,&pend,10);

    if(c > 65535 || c < 0)
    {
        pop->errflag = POPERR_BOUNDS;
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"GetUNumber: %d\n",c););

    return c;
}

static PortObject *_POParseVar(POParser *pop)
{
    PortObject *pox;
    char *name;

    name  = POParserName(pop);

    if(!name)
    {
        pop->pos++;
        pop->errflag = POPERR_NO_NAME;
        return NULL;
    }

    pox = PortVarTableFind(pop->pvTable, name);
    free(name);

    if(!pox)
    {
        pop->errflag = POPERR_BAD_VARIABLE;
        return NULL;
    }

    pox = PortObjectDup(pox);

    if(!pox)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return NULL;
    }

    return pox;
}

/*
 * Sets the PORT_OBJECT_NOT_FLAG flag on each port object item in the list
 */
static void _PONegateList(PortObject *po)
{
    PortObjectItem *poi;
    SF_LNODE * pos;

    if(!po) return;

    /* disable the NOT'd ports */
    for(poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
        poi != 0;
        poi=(PortObjectItem*)sflist_next(&pos) )
    {
        poi->flags ^= PORT_OBJECT_NOT_FLAG;
    }
}

static PortObject *_POParsePort(POParser *pop)
{
    uint16_t hport, lport;
    char c;
    PortObject *po = PortObjectNew();

    if(!po)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return NULL;
    }

    pop->token[0]=0;

    /* The string in pop should only be of the form <port> or <port>:<port> */
    lport = POParserGetShort(pop);

    if(pop->errflag)
    {
        PortObjectFree(po);
        return NULL;
    }

    c = POPPeekChar(pop);

    if( c == ':' ) /* half open range */
    {
        POPGetChar(pop);
        c = POPPeekChar(pop);

        if (((c == 0) && (pop->slen == 0)) ||
            (c == ','))
        {
            /* Open ended range, highport is 65k */
            hport = MAXPORTS-1;
            PortObjectAddRange(po, lport, hport, 0);
            return po;
        }

        if( !isdigit((int)c) ) /* not a number */
        {
            pop->errflag = POPERR_NOT_A_NUMBER;
            PortObjectFree(po);
            return NULL;
        }

        hport = POParserGetShort(pop);

        if( pop->errflag )
        {
            PortObjectFree(po);
            return NULL;
        }

        if(lport > hport)
        {
            pop->errflag = POPERR_INVALID_RANGE;
            PortObjectFree(po);
            return NULL;
        }

        PortObjectAddRange(po, lport, hport, 0);
    }
    else
    {
        PortObjectAddPort(po, lport, 0);
    }

    return po;
}

static PortObject* _POParseString(POParser *pop)
{
    PortObject     * po;
    PortObject     * potmp = NULL;
    int              local_neg = 0;
    char             c;
    int              list_count = 0;

    po = PortObjectNew();

    if(!po)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return NULL;
    }

    while( (c = POPGetChar2(pop)) != 0 )
    {
        if(c == '!')
        {
            local_neg = 1;
            continue;
        }

        if(c == '$')
        {
            /* Don't dup this again - the returned PortObject has already
             * been dup'ed */
            potmp = _POParseVar(pop);
        }
        /* Start of a list. Tokenize list and recurse on it */
        else if(c == '[')
        {
            POParser local_pop;
            char *tok;
            const char *end;

            list_count++;

            if( (end = strrchr(pop->s, (int)']')) == NULL )
            {
                pop->errflag = POPERR_NO_ENDLIST_BRACKET;
                PortObjectFree(po);
                return NULL;
            }

            if( (tok = SnortStrndup(pop->s, end - pop->s)) == NULL)
            {
                pop->errflag = POPERR_MALLOC_FAILED;
                PortObjectFree(po);
                return NULL;
            }

            POParserInit(&local_pop, tok, pop->pvTable);

            /* Recurse */
            potmp = _POParseString(&local_pop);
            free(tok);

            if(!potmp)
            {
                pop->errflag = local_pop.errflag;
                PortObjectFree(po);
                return NULL;
            }

            /* Advance "cursor" to end of this list */
            for(; c && pop->s != end; c = POPGetChar2(pop))
                ;
        }
        else if(c == ']')
        {
            list_count--;

            if(list_count < 0)
            {
                pop->errflag = POPERR_EXTRA_BRACKET;
                PortObjectFree(po);
                return NULL;
            }

            continue;
        }
        else
        {
            POPUnGetChar(pop);

            potmp = _POParsePort(pop);
        }

        if(!potmp)
        {
            PortObjectFree(po);
            return NULL;
        }

        if(local_neg)
        {
            /* Note: this intentionally only sets the negation flag! */
            /* The actual negation will take place when normalization is called */
            _PONegateList(potmp);

            local_neg = 0;
        }

        if(PortObjectAddPortObject(po, potmp, &pop->errflag))
        {
            PortObjectFree(po);
            PortObjectFree(potmp);
            return NULL;
        }

        if (potmp)
        {
            PortObjectFree(potmp);
            potmp = NULL;
        }
    }

    /* Check for mis-matched brackets */
    if(list_count)
    {
        if(list_count > 0) pop->errflag = POPERR_NO_ENDLIST_BRACKET;
        else pop->errflag = POPERR_EXTRA_BRACKET;

        PortObjectFree(po);
        return NULL;
    }

    return po;
}

/*
*   PortObject : name value
*   PortObject : name [!][ value value value ... ]
*
*   value : [!]port
*           [!]low-port[:high-port]
*
*  inputs:
*  pvTable - PortVarTable to search for PortVar references in the current PortVar
*      pop - parsing structure
*        s - string with port object text
*
* nameflag - indicates a name must be present, this allows usage for
*            embedded rule or portvar declarations of portlists
* returns:
*      (PortObject *) - a normalized version
*/
PortObject * PortObjectParseString ( PortVarTable * pvTable, POParser * pop,
                                     const char * name, const char * s , int nameflag )
{
    PortObject      *po, *potmp;

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"PortObjectParseString: %s\n",s););

    POParserInit( pop, s, pvTable );

    po = PortObjectNew();
    if(!po)
    {
        pop->errflag=POPERR_MALLOC_FAILED;
        return 0;
    }

    if( nameflag ) /* parse a name */
    {
        po->name = POParserName( pop );
        if(!po->name )
        {
            pop->errflag=POPERR_NO_NAME;
            PortObjectFree(po);
            return 0;
        }
    }
    else
    {
        if( name )
            po->name = SnortStrdup(name);
        else
            po->name = SnortStrdup("noname");
    }

   // LogMessage("PortObjectParseString: po->name=%s\n",po->name);

    potmp = _POParseString(pop);

    if(!potmp)
    {
        PortObjectFree(po);
        return NULL;
    }

    PortObjectNormalize(potmp);

    if(PortObjectAddPortObject(po, potmp, &pop->errflag))
    {
        PortObjectFree(po);
        PortObjectFree(potmp);
        return NULL;
    }

    PortObjectFree(potmp);

    return po;
}
const char * PortObjectParseError( POParser * pop )
{
    switch( pop->errflag )
    {
    case POPERR_NO_NAME:            return "no name";
    case POPERR_NO_ENDLIST_BRACKET: return "no end of list bracket."
                                           " Elements must be comma seperated,"
                                           " and no spaces may appear between"
                                           " brackets.";
    case POPERR_NOT_A_NUMBER:       return "not a number";
    case POPERR_EXTRA_BRACKET:      return "extra list bracket";
    case POPERR_NO_DATA:            return "no data";
    case POPERR_ADDITEM_FAILED:     return "add item failed";
    case POPERR_MALLOC_FAILED:      return "mem alloc failed";
    case POPERR_INVALID_RANGE:      return "invalid port range";
    case POPERR_DUPLICATE_ENTRY:    return "duplicate ports in list";
    case POPERR_BOUNDS:             return "value out of bounds for a port";
    case POPERR_BAD_VARIABLE:       return "unrecognized variable";
    default:
        break;
    }
    return "unknown POParse error";
}


/*
*
*    PORT VAR TABLE FUNCTIONS
*
*/

/*
*  Create a PortVar Table
*
*  The PortVar table used to store and lookup Named PortObjects
*/
PortVarTable * PortVarTableCreate(void)
{
    PortObject * po;
    SFGHASH * h;

    /*
     * This is used during parsing of config,
     * so 1000 entries is ok, worst that happens is somewhat slower
     * config/rule processing.
     */
    h = sfghash_new(1000,0,0,PortObjectFree);
    if( !h )
        return 0;

    /* Create default port objects */
    po = PortObjectNew();
    if( !po )
         return 0;

    /* Default has an ANY port */
    PortObjectAddPortAny( po );

    /* Add ANY to the table */
    PortVarTableAdd( h, po );

    return h;
}

/*
*   PortVarTableAdd()
*
*   returns
*       -1 : error, no memory...
*        0 : added
*        1 : in table
*/
int PortVarTableAdd( PortVarTable * h, PortObject * po )
{
    int stat;
    stat = sfghash_add(h,po->name,po);
    if( stat == SFGHASH_INTABLE )
        return 1;
    if( stat == SFGHASH_OK )
        return 0;
    return -1;
}

PortObject * PortVarTableFind( PortVarTable * h, const char * name )
{
    if (!h || !name)
        return NULL;

    return (PortObject*)sfghash_find(h,name);
}

/*
    This deletes the table, the PortObjects and PortObjectItems,
    and rule list.
*/
int PortVarTableFree(PortVarTable * pvt)
{
     if( pvt )
     {
        sfghash_delete( pvt );
     }
     return 0;
}


/*
   TEST DRIVER

  PorObjects use the follow creation strategy

     po = PortObjectNew();
     PortObjectAddPort( po, 80,   0  );
     PortObjectAddPort( po, 8080, 0  );
     PortObjectAddPort( po, 8138, 0  );
     PortTableAddObject( p, po, k++ );

  PortVarTable just stores PorObjects by Name

*/
//#define MAIN_PORTOBJECT

//char * sample1="http [ 80 8100:8200 !8150 ]";
//char * sample2="httpx [ !http 8120 ]";

#ifdef  MAIN_PORTOBJECT
int main( int argc, char ** argv )
{
     PortVarTable * pvTable;
     PortTable  * p;
     PortObject * po;
     POParser pop;
     int i;
     int k=1;
     int debug=0;
     int names=1;

     int lrc =100;
     int lrp =20;

     char * portlist;

     for(i=1;i<argc;i++)
     {
         if( strcmp(argv[i],"-debug")==0 ) debug=1;
         if( strcmp(argv[i],"-lrc")==0 ) lrc=atoi(argv[++i]);
         if( strcmp(argv[i],"-lrp")==0 ) lrp=atoi(argv[++i]);
     }

     /*
     Create a PortVar table - this is automatic and not necessary
     */
     pvTable=PortVarTableCreate();
     if( !pvTable  )
     {
         LogMessage("Cound not init port variables\n");
         exit(1);
     }

     /*
     Create a table for src and one for dst
     we'll only add specific ports, no ANY ports,
     but ranges are ok.
     */
     p = PortTableNew();
     if(!p)
     {
         LogMessage("no memory\n");
         exit(0);
     }
     p->pt_lrc=lrc; // large rule count - primary

     for(i=1;i<argc;i++)
     {
        if( argv[i][0] == '-' )
        {
            if( strcmp(argv[i],"-names")==0 ) names=0;/* disable names in var input*/
            continue;
        }

        portlist = argv[i];
        //if( i==1) portlist = sample1;
        //if( i==2) portlist = sample2;
        //LogMessage("PortObject : '%s' \n",portlist);

        /*
        This is seperate fom PortVar's since some rules may declare these inline
        */
        po = PortObjectParseString ( pvTable, &pop, argv[i], PORTLISTS, names/* bool 0/1 - name required in parse */);
        if( !po )
        {
            LogMessage(">>Bogus PortObject Definition (pos=%d,errflag=%d)\n>>%s\n>>%*s\n",
                   pop.pos,pop.errflag,PORTLISTS,pop.pos,"^");
            continue;  /* invalid parse - no port object to add */
        }

        PortObjectPrint ( po );

        if( PortVarTableAdd( pvTable, po ) ) /* requires a name : portlist http [ portlist ]*/
        {
            LogMessage("error: named port var '%s' already in table \n",po->name);
        }

        // Lets test the lookup ...
        if( !PortVarTableFind(pvTable,po->name) )
        {
            LogMessage("Could not find PortVar: %s\n",po->name);
            exit(0);
        }

        /*
        Assume each PortVar object has one rule and add it to the PortTable
        PortObjects that are defined in rules have no names and are not
        added to the PortVar table
        */
        PortTableAddObject(p,po,k++/*rule id*/);
     }


     PortTableCompile( p );

     //PortTablePrintRules( p );

     //if(debug)
         PortTablePrintPortGroups( p );

     //PortTablePrintPortPortObjects( p );

     PortTableDumpPortRules(  p );

     LogMessage("\n");
     LogMessage("#rule and port groups compiled successfully\n");

     return 0;
}
#endif

