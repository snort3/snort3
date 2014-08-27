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
  sfportobject.h
 
  Port List Object Management

  author: marc norton

  Hierarchy:

	PortTable -> PortObject's 

	PortVar -> PortObject

	PortObject -> PortObjectItems (port or port range)

 */
#ifndef SFPORTOBJECT_H
#define SFPORTOBJECT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/sfghash.h"
#include "utils/bitop_funcs.h"
#include "utils/sflsq.h"

#define SFPO_MAX_LPORTS 500
#define SFPO_MAX_PORTS 65536

typedef SFGHASH  PortVarTable;

/*
 * PortObjectItem Flags
 */
#define PORT_OBJECT_NOT_FLAG 1

#define PORT_OBJECT_PORT  1
#define PORT_OBJECT_RANGE 2
#define PORT_OBJECT_ANY   3

/*
 * Port Object Item supports
 * port, lowport:highport, portlist
 */
typedef struct _PortObjectItem_s {
    
    int type;       /*  ANY, RANGE, PORT */
    int flags;       /* NOT */
    
    uint16_t hport;   /* hi port */
    uint16_t lport;   /* lo port */

    uint16_t cur_port; /* internal - first/next */
    uint16_t tmp;

}PortObjectItem;


/*
*  PortObject supports a set of PortObjectItems
*
*  A Port Set may include one or more of the following 
*      Port
*      Port Range
*      List of Ports mixed with Port Ranges
*/

struct PortList_x{ /* not used yet */
	char           * name;      /* user name - always use strdup or malloc for this*/
    SF_LIST        * item_list; /* list of port and port-range items */
};

struct PortObject{
	char           * name;      /* user name - always use strdup or malloc for this*/
	int              id;        /* internal tracking - compiling sets this value */
    SF_LIST        * item_list; /* list of port and port-range items */
    SF_LIST        * rule_list; /* list of rules  */
    void           * data;      /* user data, PORT_GROUP based on rule_list - only used by any-any ports */
    void           (*data_free)(void *);
};

struct PortObject2{
	char           * name;      /* user name - always use strdup or malloc for this*/
	int              id;        /* internal tracking - compiling sets this value */
    SF_LIST        * item_list; /* list of port and port-range items */
    SFGHASH        * rule_hash; /* hash of rule (rule-indexes) in use */
    int              port_cnt;  /* count of ports using this object */
    BITOP          * bitop;     /* for collecting ports that use this object */
    void           * data;      /* user data, PORT_GROUP based on rule_hash  */
    void           (*data_free)(void *);
};

/*
    Port Table
*/
struct PortTable {

    /* turns on group optimization, better speed-but more memory 
     * otherwise a single merged rule group is used.
     */
    int pt_optimize;

    /* save the users input port objects in this list 
     * rules may be added after creation of a port object
     * but the ports are not modified.
     */
    SF_LIST * pt_polist;
    int       pt_poid;

    /*
    * Array of lists of PortObject pointers to unique PortObjects, 
    * the associated rule lists are stored in Data elements in rh,
    * the keys are the address of the PortObjects
    */
    SF_LIST * pt_port_lists[SFPO_MAX_PORTS];

    /* Compiled / merged port object hash table */
    SFGHASH * pt_mpo_hash;
    SFGHASH * pt_mpxo_hash;

    SF_LIST * pt_plx_list;

    /*  a single rule list with all rules merged together */
    SF_LIST * pt_merged_rule_list; 

    /* 
    * Final Port/Rule Groupings, one port object per port, or null
    */
    PortObject2 * pt_port_object[SFPO_MAX_PORTS];
        
    int pt_lrc; /* large rule count, this many rules is a large group */

    /* Stats */
    int single_merges; /* single PortObject on a port */
    int small_merges;  /* small port objects merged into a bigger object */
    int large_single_merges; /* 1 large + some small objects */
    int large_multi_merges; /* >1 large object merged + some small objects */
    int non_opt_merges;

};

typedef struct RulePortTables{

    PortTable * tcp_src, * tcp_dst;
    PortTable * udp_src, * udp_dst;
    PortTable * icmp_src,* icmp_dst;
    PortTable * ip_src,  * ip_dst;
    
    PortObject * tcp_anyany;
    PortObject * udp_anyany;
    PortObject * icmp_anyany;
    PortObject * ip_anyany;
    
    PortObject * tcp_nocontent; 
    PortObject * udp_nocontent; 
    PortObject * icmp_nocontent; 
    PortObject * ip_nocontent; 

}rule_port_tables_t;


#define POPERR_NO_NAME            1
#define POPERR_NO_ENDLIST_BRACKET 2
#define POPERR_NOT_A_NUMBER       3
#define POPERR_EXTRA_BRACKET      4
#define POPERR_NO_DATA            5
#define POPERR_ADDITEM_FAILED     6
#define POPERR_MALLOC_FAILED      7 
#define POPERR_INVALID_RANGE      8
#define POPERR_DUPLICATE_ENTRY    9
#define POPERR_BOUNDS             10
#define POPERR_BAD_VARIABLE       11

#define POP_MAX_BUFFER_SIZE 256
struct POParser{
    const char * s;         /* current string pointer */
    int    slen;      /* bytes left in string */
    int    pos;       /* position in string of last GetChar() */
    char   token[POP_MAX_BUFFER_SIZE+4]; /* single number, or range, or not flag */
    int    errflag;
    /* for handling PortObject references when parsing */
    PortObject   * po_ref;
    SF_LNODE     * poi_pos;
    PortVarTable * pvTable;
};

/*
	Prototypes
*/

/*
*   Port List Table
*
*    The PortTable provides support to analyze the Port List objects defined by
*    the user as either PortVar entries or simply as inline rule port
*    list declarations.
*/
PortTable  * PortTableNew      (void);
void         PortTableFree( PortTable  *p );
int          PortTableAddObject( PortTable *p, PortObject * po );
int          PortTableAddObjectRaw( PortTable *p, PortObject * po );
int          PortTableAddRule  ( PortTable * p, int port, int rule );
int          PortTableCompile  ( PortTable * P);
void         PortTablePrintInputEx( PortTable * p, 
                    void (*rule_index_map_print)(int index, char *buf, int bufsize) );
int          PortTablePrintCompiledEx( PortTable * p, 
                    void (*rule_index_map_print)(int index, char *buf, int bufsize) );
PortObject * PortTableFindPortObjectByPort( PortTable * pt , int port );
PortObject * PortTableFindInputPortObjectName(PortTable * pt, char * po_name);
PortObject * PortTableFindInputPortObjectPorts( PortTable * pt , PortObject * po );
/*
    Port List Object
*/
PortObject     * PortObjectNew        ( void );
PortObject2    * PortObject2New       (int nrules/*guess at this */);
void             PortObjectFree       ( void *  p );
void             PortObject2Free      ( void *  p );
int              PortObjectSetName    ( PortObject * po, const char * name );
PortObjectItem * PortObjectItemNew    ( void );
PortObjectItem * PortObjectItemDup    ( PortObjectItem * poi );
void             PortObjectItemFree    ( PortObjectItem * poi );
int              PortObjectAddItem    ( PortObject * po, PortObjectItem * poi, int *errflag);
int              PortObjectAddPortObject ( PortObject * podst, PortObject * posrc, int *errflag);
int              PortObjectAddPort    ( PortObject * po, int port, int not_flag );
int              PortObjectAddRange   ( PortObject * po, int lport, int hport, int not_flag );
int              PortObjectAddRule    ( PortObject * po, int rule );
int              PortObjectAddPortAny ( PortObject * po );
PortObject     * PortObjectDup        ( PortObject * po );
PortObject2    * PortObject2Dup       ( PortObject * po );
PortObject     * PortObjectDupPorts   ( PortObject * po );
int            * PortObjectExtractRuleArray( PortObject * po, int * nrules );
int            * PortObject2ExtractRuleArray( PortObject2 * po, int * nrules );

int              PortObjectNormalize   ( PortObject * po );
int              PortObjectNegate      ( PortObject * po );
int              PortObjectEqual       ( PortObject * poa, PortObject * bob );

void             PortObjectSetAny      ( PortObject * po );
int              PortObjectPortCount   ( PortObject * po );
int              PortObjectHasPort     ( PortObject * po, int port );
int              PortObjectHasNot      ( PortObject * po );
int              PortObjectIsPureNot   ( PortObject * po );
int              PortObjectHasAny      ( PortObject * po );
int              PortObjectIncludesPort(PortObject * po, int port );
char           * PortObjectCharPortArray ( char * parray, PortObject * po, int * nports );
int              PortObjectRemovePorts( PortObject * a,  PortObject * b );
PortObject     * PortObjectAppend(PortObject * poa, PortObject * pob );
PortObject     * PortObjectAppendPortObject(PortObject * poa, PortObject * pob );
PortObject2    * PortObject2AppendPortObject(PortObject2 * poa, PortObject * pob );
PortObject2    * PortObject2AppendPortObject2(PortObject2 * poa, PortObject2 * pob );
PortObject     * PortObjectAppendEx(PortObject * poa, PortObject * pob );
PortObject2    * PortObjectAppendEx2(PortObject2 * poa, PortObject * pob );
int              PortTableNormalizeInputPortObjects( PortTable *p );
int              PortTableCompileMergePortObjects( PortTable * p );
int              PortTableConsistencyCheck( PortTable *p );
void             PortTablePrintInput( PortTable * p );
void             PortTablePrintUserRules( PortTable * p );
void             PortTablePrintPortGroups( PortTable * p );
void             PortTablePrintPortPortObjects( PortTable * p );
int              PortVarTableFree(PortVarTable * pvt);

void             PortObjectPrint       ( PortObject * po );
void             PortObjectPrintPorts  ( PortObject * po );
void             PortObjectPrintPortsRaw(PortObject * po );
void             PortObject2PrintPorts ( PortObject2 * po );
void             PortObject2Print      ( PortObject2 * po );
int              PortObjectPrintDetails( PortObject * po );

void PortObjectPrintEx(PortObject * po, 
        void (*print_index_map)(int index, char *buf, int bufsize) );
void PortObject2PrintEx(PortObject2 * po, 
        void (*print_index_map)(int index, char *buf, int bufsize) );
void PortTableSortUniqRules( 
        PortTable * p 
        );
void RuleListSortUniq( 
        SF_LIST * rl 
        );

/* 
    PortVarTable 
	
	port lists may be defined as 'name port-list' 
*/
PortVarTable * PortVarTableCreate (void);
int            PortVarTableAdd    ( PortVarTable * pvt, PortObject * po );
PortObject   * PortVarTableFind   ( PortVarTable * pvt, const char * name );


/* 
   PortVars are internally stored in PortObjects 
   This function parses PortVar strings into PortObjects
*/
PortObject *  PortObjectParseString ( PortVarTable * pvTable, POParser * pop, const char * name,  const char * s,int nameflag );
const char * PortObjectParseError( POParser * p ); 
#endif
