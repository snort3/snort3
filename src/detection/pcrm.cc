//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

/*
**  Marc Norton <mnorton@sourcefire.com>
**  Dan Roelker <droelker@sourcefire.com>
**
**  NOTES
**  5.15.02   - Initial version of pcrm.c distributed. - Norton/Roelker
**
**  Packet Classificationa and Rule Manager
**
**
**  A Fast Packet Classification method for Rule and Pattern Matching in SNORT
**  --------------------------------------------------------------------------
**
**  A simple method for grouping rules into lists and looking them up quickly
**  in realtime.
**
**  There is a natural problem when aggregating rules into pattern groups for
**  performing multi-pattern matching not seen with single pattern Boyer-Moore
**  strategies.  The problem is how to group the rules efficiently when
**  considering that there are multiple parameters which govern what rules to
**  apply to each packet or connection. The paramters, sip, dip, sport, dport,
**  and flags form an enormous address space of possible packets that
**  must be tested in realtime against a subset of rule patterns. Methods to
**  group patterns precisely based on all of these parameters can quickly
**  become complicated by both algorithmic implications and implementation
**  details.  The procedure described herein is quick and simple.
**
**  The methodology presented here to solve this problem is based on the
**  premise that we can use the source and destination ports to isolate
**  pattern groups for pattern matching, and rely on an event validation
**  procedure to authenticate other parameters such as sip, dip and flags after
**  a pattern match is made. An instrinsic assumption here is that most sip
**  and dip values will be acceptable and that the big gain in performance
**  is due to the fact that by isolating traffic based on services (ports)
**  we gain the most benefit.  Additionally, and just as important, is the
**  requirement that we can perform a multi-pattern recognition-inspection phase
**  on a large set of patterns many times quicker than we can apply a single
**  pattern test against many single patterns.
**
**  The current implementation assumes that for each rule the src and dst ports
**  each have one of 2 possible values.  Either a specific port number or the
**  ANYPORT designation. This does allow us to handle port ranges and NOT port
**  rules as well.
**
**  We make the following assumptions about classifying packets based on ports:
**
**    1) There are Unique ports which represent special services.  For example,
**       ports 21,25,80,110,etc.
**
**    2) Patterns can be grouped into Unique Pattern groups, and a Generic
**       Pattern Group
**       a) Unique pattern groups exist for source ports 21,25,80,110,etc.
**       b) Unique pattern groups exist for destination ports 21,25,80,etc.
**       c) A Generic pattern group exists for rules applied to every
**          combination of source and destination ports.
**
**  We make the following assumptions about packet traffic:
**
**    1) Well behaved traffic has one Unique port and one ephemeral port for
**       most packets and sometimes legitimately, as in the case of DNS, has
**       two unique ports that are the same. But we always determine that
**       packets with two different but Unique ports is bogus, and should
**       generate an alert.  For example, if you have traffic going from
**       port 80 to port 20.
**
**    2) In fact, state could tell us which side of this connection is a
**       service and which side is a client. Than we could handle this packet
**       more precisely, but this is a rare situation and is still bogus. We
**       can choose not to do pattern inspections on these packets or to do
**       complete inspections.
**
**  Rules are placed into each group as follows:
**
**    1) Src Port == Unique Service, Dst Port == ANY -> Unique Src Port Table
**       Src Port == Unique Service, Dst Port ==
**       Unique -> Unique Src & Dst Port Tables
**    2) Dst Port == Unqiue Service, Src Port == ANY -> Unique Dst Port Table
**       Dst Port == Unqiue Service, Src Port ==
**       Unique -> Unique Dst & Src Port Tables
**    3) Dst Port == ANY, Src Port == ANY -> Generic Rule Set,
**       And add to all Unique Src/Dst Rule Sets that have entries
**    4) !Dst or !Src Port is the same as ANY Dst or ANY Src port respectively
**    5) DstA:DstB is treated as an ANY port group, same for SrcA:SrcB
**
**  Initialization
**  --------------
**  For each rule check the dst-port, if it's specific, then add it to the
**  dst table.  If the dst-port is Any port, then do not add it to the dst
**  port table. Repeat this for the src-port.
**
**  If the rule has Any for both ports then it's added generic rule list.
**
**  Also, fill in the Unique-Conflicts array, this indicates if it's OK to have
**  the same Unique service port for both destination and source. This will
**  force an alert if it's not ok.  We optionally pattern match against this
**  anyway.
**
**  Processing Rules
**  -----------------
**  When packets arrive:
**
**   Categorize the Port Uniqueness:
**
**   a)Check the DstPort[DstPort] for possible rules,
**     if no entry,then no rules exist for this packet with this destination.
**
**   b)Check the SrcPort[SrcPort] for possible rules,
**     if no entry,then no rules exist for this packet with this source.
**
**   Process the Uniqueness:
**
**   If a AND !b has rules or !a AND b has rules then
**      match against those rules
**
**   If a AND b have rules then
**      if( sourcePort != DstPort )
**         Alert on this traffic and optionally match both rule sets
**      else if( SourcePort == DstPort )
**         Check the Unique-Conflicts array for allowable conflicts
**             if( NOT allowed )
**	       Alert on this traffic, optionally match the rules
**	    else
**	       match both sets of rules against this traffic
**
**   If( !a AND ! b )  then
**      Pattern Match against the Generic Rules ( these apply to all packets)
**
**
**  example.c
**  ---------
**
**   PORT_RULE_MAP * prm;
**   PORT_GROUP  *src, *dst, *generic;
**
**   RULE * prule; //user defined rule structure for user rules
**
**   prm = prmNewMap();
**
**   for( each rule )
**   {
**      prule = ....get a rule pointer
**
**      prmAddRule( prm, prule->dport, prule->sport, prule );
**   }
**
**   prmCompileGroups( prm );
**
**   while( sniff-packets )
**   {
**      ....
**
**      stat = prmFindRuleGroup( prm, dport, sport, &src, &dst, &generic );
**      switch( stat )
**      {
**         case 0:  // No rules at all
**          break;
**         case 1:  // Dst Rules
**           // pass 'dst->pgPatData', 'dst->pgPatDataUri' to the pattern engine
**          break;
**         case 2:  // Src Rules
**           // pass 'src->pgPatData', 'src->pgPatDataUri' to the pattern engine
**          break;
**         case 3:  // Src/Dst Rules - Both ports represent Unique service ports
**           // pass 'src->pgPatData' ,'src->pgPatDataUri' to the pattern engine
**           // pass 'dst->pgPatData'  'src->pgPatDataUri' to the pattern engine
**          break;
**         case 4:  // Generic Rules Only
**           // pass 'generic->pgPatData' to the pattern engine
**           // pass 'generic->pgPatDataUri' to the pattern engine
**          break;
**      }
**   }
**
*/

#include "pcrm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "fpcreate.h"
#include "snort.h"

/*
**
**  NAME
**    prmNewMap::
**
**  DESCRIPTION
**    Allocate new PORT_RULE_MAP and return pointer.
**
**  FORMAL INPUTS
**    None
**
**  FORMAL OUTPUT
**    PORT_RULE_MAP * - NULL if failed, ptr otherwise.
**
*/
PORT_RULE_MAP* prmNewMap(void)
{
    PORT_RULE_MAP* p;

    p = (PORT_RULE_MAP*)calloc(1, sizeof(PORT_RULE_MAP) );

    return p;
}

/*
**
**  NAME
**    prmNewByteMap::
**
**  DESCRIPTION
**    Allocate new BYTE_RULE_MAP and return pointer.
**
**  FORMAL INPUTS
**    None
**
**  FORMAL OUTPUT
**    BYTE_RULE_MAP * - NULL if failed, ptr otherwise.
**
*/
BYTE_RULE_MAP* prmNewByteMap(void)
{
    BYTE_RULE_MAP* p;

    p = (BYTE_RULE_MAP*)calloc(1, sizeof(BYTE_RULE_MAP) );

    return p;
}

/*
**
**  NAME
**    prmxFreeGroup::
**
**  DESCRIPTION
**    Frees a PORT_GROUP of it's RuleNodes.
**
**  FORMAL INPUTS
**    PORT_GROUP * - port group to free
**
**  FORMAL OUTPUT
**    None
**
*/
static void prmxFreeGroup(PORT_GROUP* pg)
{
    RULE_NODE* rn, * rx;

    rn = pg->pgHead;
    while ( rn )
    {
        rx = rn->rnNext;
        free(rn);
        rn = rx;
    }
    pg->pgHead = NULL;

    rn = pg->pgHeadNC;
    while ( rn )
    {
        rx = rn->rnNext;
        free(rn);
        rn = rx;
    }
    pg->pgHeadNC = NULL;

    rn = pg->pgUriHead;
    while ( rn )
    {
        rx = rn->rnNext;
        free(rn);
        rn = rx;
    }
    pg->pgUriHead = NULL;
}

/*
**
**  NAME
**    prmFreeMap
**
**  DESCRIPTION
**    Frees the memory utilized by a PORT_RULE_MAP.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to free
**
**  FORMAL OUTPUT
**    None
**
*/
void prmFreeMap(PORT_RULE_MAP* p)
{
    int i;

    if ( p )
    {
        for (i=0; i<MAX_PORTS; i++)
        {
            if (p->prmSrcPort[i])
            {
                prmxFreeGroup(p->prmSrcPort[i]);
                free(p->prmSrcPort[i]);
            }
        }

        for (i=0; i<MAX_PORTS; i++)
        {
            if (p->prmDstPort[i])
            {
                prmxFreeGroup(p->prmDstPort[i]);
                free(p->prmDstPort[i]);
            }
        }

        if (p->prmGeneric)
        {
            prmxFreeGroup(p->prmGeneric);
            free(p->prmGeneric);
        }

        free(p);
    }
}

/*
**
**  NAME
**    prmFreeByteMap
**
**  DESCRIPTION
**    Frees the memory utilized by a BYTE_RULE_MAP.
**
**  FORMAL INPUTS
**    BYTE_RULE_MAP * - BYTE_RULE_MAP to free
**
**  FORMAL OUTPUT
**    None
**
*/
void prmFreeByteMap(BYTE_RULE_MAP* p)
{
    int i;

    if ( p )
    {
        for (i=0; i<256; i++)
        {
            prmxFreeGroup(&p->prmByteGroup[i]);
        }

        prmxFreeGroup(&p->prmGeneric);

        free(p);
    }
}

/*
**
**  NAME
**    prmxAddPortRule::
**
**  DESCRIPTION
**    Adds a RULE_NODE to a PORT_GROUP.  This particular
**    function is specific in that it adds "content" rules.
**    A "content" rule is a snort rule that has a content
**    flag.
**
**    Each RULE_NODE in a PORT_GROUP is given a RULE_NODE
**    ID.  This allows us to track particulars as to what
**    rules have been alerted upon, and allows other neat
**    things like correlating events on different streams.
**    The RULE_NODE IDs may not be consecutive, because
**    we can add RULE_NODES into "content", "uri", and
**    "no content" lists.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to add the rule to.
**    RULE_PTR - void ptr to the user information
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure
**
*/
int prmxAddPortRule(PORT_GROUP* p, RULE_PTR rd)
{
    if ( !p->pgHead )
    {
        p->pgHead = (RULE_NODE*)calloc(1,sizeof(RULE_NODE) );
        if ( !p->pgHead )
            return 1;

        p->pgHead->rnNext      = 0;
        p->pgHead->rnRuleData  = rd;
        p->pgTail              = p->pgHead;
    }
    else
    {
        p->pgTail->rnNext = (RULE_NODE*)calloc(1,sizeof(RULE_NODE) );
        if (!p->pgTail->rnNext)
            return 1;

        p->pgTail             = p->pgTail->rnNext;
        p->pgTail->rnNext     = 0;
        p->pgTail->rnRuleData = rd;
    }

    /*
    **  Set RULE_NODE ID to unique identifier
    */
    p->pgTail->iRuleNodeID = p->pgCount;

    /*
    **  Update the total Rule Node Count for this PORT_GROUP
    */
    p->pgCount++;

    p->pgContentCount++;

    return 0;
}

/*
**
**  NAME
**    prmxAddPortRuleUri::
**
**  DESCRIPTION
**    Adds a RULE_NODE to a PORT_GROUP.  This particular
**    function is specific in that it adds "uri" rules.
**    A "uri" rule is a snort rule that has a uri
**    flag.
**
**    Each RULE_NODE in a PORT_GROUP is given a RULE_NODE
**    ID.  This allows us to track particulars as to what
**    rules have been alerted upon, and allows other neat
**    things like correlating events on different streams.
**    The RULE_NODE IDs may not be consecutive, because
**    we can add RULE_NODES into "content", "uri", and
**    "no content" lists.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to add the rule to.
**    RULE_PTR - void ptr to the user information
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure
**
*/
int prmxAddPortRuleUri(PORT_GROUP* p, RULE_PTR rd)
{
    if ( !p->pgUriHead )
    {
        p->pgUriHead = (RULE_NODE*)calloc(1, sizeof(RULE_NODE) );
        if ( !p->pgUriHead )
            return 1;

        p->pgUriTail              = p->pgUriHead;
        p->pgUriHead->rnNext      = 0;
        p->pgUriHead->rnRuleData  = rd;
    }
    else
    {
        p->pgUriTail->rnNext = (RULE_NODE*)calloc(1, sizeof(RULE_NODE) );
        if ( !p->pgUriTail->rnNext)
            return 1;

        p->pgUriTail             = p->pgUriTail->rnNext;
        p->pgUriTail->rnNext     = 0;
        p->pgUriTail->rnRuleData = rd;
    }

    /*
    **  Set RULE_NODE ID to unique identifier
    */
    p->pgUriTail->iRuleNodeID = p->pgCount;

    /*
    **  Update the total Rule Node Count for this PORT_GROUP
    */
    p->pgCount++;

    p->pgUriContentCount++;

    return 0;
}

/*
**
**  NAME
**    prmxAddPortRuleNC::
**
**  DESCRIPTION
**    Adds a RULE_NODE to a PORT_GROUP.  This particular
**    function is specific in that it adds "no content" rules.
**    A "no content" rule is a snort rule that has no "content"
**    or "uri" flag, and hence does not need to be pattern
**    matched.
**
**    Each RULE_NODE in a PORT_GROUP is given a RULE_NODE
**    ID.  This allows us to track particulars as to what
**    rules have been alerted upon, and allows other neat
**    things like correlating events on different streams.
**    The RULE_NODE IDs may not be consecutive, because
**    we can add RULE_NODES into "content", "uri", and
**    "no content" lists.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to add the rule to.
**    RULE_PTR - void ptr to the user information
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure
**
*/
int prmxAddPortRuleNC(PORT_GROUP* p, RULE_PTR rd)
{
    if ( !p->pgHeadNC )
    {
        p->pgHeadNC = (RULE_NODE*)calloc(1,sizeof(RULE_NODE) );
        if ( !p->pgHeadNC )
            return 1;

        p->pgTailNC             = p->pgHeadNC;
        p->pgHeadNC->rnNext     = 0;
        p->pgHeadNC->rnRuleData = rd;
    }
    else
    {
        p->pgTailNC->rnNext = (RULE_NODE*)calloc(1,sizeof(RULE_NODE) );
        if (!p->pgTailNC->rnNext)
            return 1;

        p->pgTailNC             = p->pgTailNC->rnNext;
        p->pgTailNC->rnNext     = 0;
        p->pgTailNC->rnRuleData = rd;
    }

    /*
    **  Set RULE_NODE ID to unique identifier
    */
    p->pgTailNC->iRuleNodeID = p->pgCount;

    /*
    **  Update the Total Rule Node Count for this PORT_GROUP
    */
    p->pgCount++;

    p->pgNoContentCount++;

    return 0;
}

/*
**
**  NAME
**    prmAddNotNode::
**
**  DESCRIPTION
**    NOT SUPPORTED YET.  Build a list of pur NOT nodes i.e. content !"this"
**    content:!"that".
**
*/
void prmAddNotNode(PORT_GROUP* pg, int id)
{
    NOT_RULE_NODE* p = (NOT_RULE_NODE*)calloc(1,sizeof( NOT_RULE_NODE));

    if ( !p )
        return;

    p->iPos = id;

    if ( !pg->pgNotRuleList )
    {
        pg->pgNotRuleList = p;
        p->next = 0;
    }
    else
    {
        p->next = pg->pgNotRuleList;
        pg->pgNotRuleList = p;
    }
}

/*
**
**  NAME
**    prmGetFirstRule::
**
**  DESCRIPTION
**    This function returns the first rule user data in
**    the "content" list of a PORT_GROUP.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - the ptr to the user data.
**
*/
RULE_PTR prmGetFirstRule(PORT_GROUP* pg)
{
    pg->pgCur = pg->pgHead;

    if ( !pg->pgCur )
        return 0;

    return pg->pgCur->rnRuleData;
}

/*
**
**  NAME
**    prmGetNextRule::
**
**  DESCRIPTION
**    Gets the next "content" rule.  This function allows easy
**    walking of the "content" rule list.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - ptr to the user data
**
*/
RULE_PTR prmGetNextRule(PORT_GROUP* pg)
{
    if ( pg->pgCur )
        pg->pgCur = pg->pgCur->rnNext;

    if ( !pg->pgCur )
        return 0;

    return pg->pgCur->rnRuleData;
}

/*
**
**  NAME
**    prmGetFirstRuleUri::
**
**  DESCRIPTION
**    This function returns the first rule user data in
**    the "uri" list of a PORT_GROUP.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - the ptr to the user data.
**
*/
RULE_PTR prmGetFirstRuleUri(PORT_GROUP* pg)
{
    pg->pgUriCur = pg->pgUriHead;

    if ( !pg->pgUriCur )
        return 0;

    return pg->pgUriCur->rnRuleData;
}

/*
**
**  NAME
**    prmGetNextRuleUri::
**
**  DESCRIPTION
**    Gets the next "uri" rule.  This function allows easy
**    walking of the "uri" rule list.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - ptr to the user data
**
*/
RULE_PTR prmGetNextRuleUri(PORT_GROUP* pg)
{
    if ( pg->pgUriCur )
        pg->pgUriCur = pg->pgUriCur->rnNext;

    if ( !pg->pgUriCur )
        return 0;

    return pg->pgUriCur->rnRuleData;
}

/*
**
**  NAME
**    prmGetFirstRuleNC::
**
**  DESCRIPTION
**    This function returns the first rule user data in
**    the "no content" list of a PORT_GROUP.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - the ptr to the user data.
**
*/
RULE_PTR prmGetFirstRuleNC(PORT_GROUP* pg)
{
    pg->pgCurNC = pg->pgHeadNC;

    if ( !pg->pgCurNC )
        return 0;

    return pg->pgCurNC->rnRuleData;
}

/*
**
**  NAME
**    prmGetNextRuleNC::
**
**  DESCRIPTION
**    Gets the next "no content" rule.  This function allows easy
**    walking of the "no content" rule list.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - ptr to the user data
**
*/
RULE_PTR prmGetNextRuleNC(PORT_GROUP* pg)
{
    if ( pg->pgCurNC )
        pg->pgCurNC = pg->pgCurNC->rnNext;

    if ( !pg->pgCurNC )
        return 0;

    return pg->pgCurNC->rnRuleData;
}

/*
**
**  NAME
**    prmAddRule::
**
**  DESCRIPTION
**    This function adds a rule to a PORT_RULE_MAP.  Depending on the
**    values of the sport and dport, the rule gets added in different
**    groups (src,dst,generic).  The values for dport and sport
**    can be: 0 -> 64K or -1 for generic (meaning that the rule applies
**    to all values.
**
**    Warning: Consider this carefully.
**    Some rules use 6000:6005 -> any  for a port designation, we could
**    add each rule to it's own group, in this case Src=6000 to 6005.
**    But we opt to add them as ANY rules for now, to reduce groups.
**
**    IMPORTANT:
**    This function adds a rule to the "content" list of rules.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to add rule to.
**    int - the dst port value.
**    int - the src port value.
**    RULE_PTR - the ptr to the user data for the rule.
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure.
**
*/
int prmAddRule(PORT_RULE_MAP* p, int dport, int sport, RULE_PTR rd)
{
    if ( dport != ANYPORT && dport < MAX_PORTS )  /* dst=21,25,80,110,139 */
    {
        p->prmNumDstRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmDstPort[dport] == NULL)
        {
            p->prmDstPort[dport] = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmDstPort[dport] == NULL)
            {
                return 1;
            }
        }

        if (p->prmDstPort[dport]->pgCount==0)
            p->prmNumDstGroups++;

        prmxAddPortRule(p->prmDstPort[ dport ], rd);
    }

    if ( sport != ANYPORT && sport < MAX_PORTS) /* src=ANY, SRC=80,21,25,etc. */
    {
        p->prmNumSrcRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmSrcPort[sport] == NULL)
        {
            p->prmSrcPort[sport] = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmSrcPort[sport] == NULL)
            {
                return 1;
            }
        }

        if (p->prmSrcPort[sport]->pgCount==0)
            p->prmNumSrcGroups++;

        prmxAddPortRule(p->prmSrcPort[ sport ], rd);
    }

    if ( sport == ANYPORT && dport == ANYPORT) /* dst=ANY, src=ANY */
    {
        p->prmNumGenericRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmGeneric == NULL)
        {
            p->prmGeneric = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmGeneric == NULL)
            {
                return 1;
            }
        }

        prmxAddPortRule(p->prmGeneric, rd);
    }

    return 0;
}

int prmAddByteRule(BYTE_RULE_MAP* p, int dport, RULE_PTR rd)
{
    if ( dport != ANYPORT && dport < 256 )  /* dst=21,25,80,110,139 */
    {
        p->prmNumRules++;
        if ( p->prmByteGroup[dport].pgCount==0 )
            p->prmNumGroups++;

        prmxAddPortRule(&(p->prmByteGroup[ dport ]), rd);
    }
    else if ( dport == ANYPORT ) /* dst=ANY, src=ANY */
    {
        p->prmNumGenericRules++;

        prmxAddPortRule(&(p->prmGeneric), rd);
    }

    return 0;
}

/*
**
**  NAME
**    prmAddRuleUri::
**
**  DESCRIPTION
**    This function adds a rule to a PORT_RULE_MAP.  Depending on the
**    values of the sport and dport, the rule gets added in different
**    groups (src,dst,generic).  The values for dport and sport
**    can be: 0 -> 64K or -1 for generic (meaning that the rule applies
**    to all values.
**
**    Warning: Consider this carefully.
**    Some rules use 6000:6005 -> any  for a port designation, we could
**    add each rule to it's own group, in this case Src=6000 to 6005.
**    But we opt to add them as ANY rules for now, to reduce groups.
**
**    IMPORTANT:
**    This function adds a rule to the "uri" list of rules.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to add rule to.
**    int - the dst port value.
**    int - the src port value.
**    RULE_PTR - the ptr to the user data for the rule.
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure.
**
*/
int prmAddRuleUri(PORT_RULE_MAP* p, int dport, int sport, RULE_PTR rd)
{
    if ( dport != ANYPORT && dport < MAX_PORTS )  /* dst=21,25,80,110,139 */
    {
        p->prmNumDstRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmDstPort[dport] == NULL)
        {
            p->prmDstPort[dport] = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmDstPort[dport] == NULL)
            {
                return 1;
            }
        }

        if (p->prmDstPort[dport]->pgCount==0)
            p->prmNumDstGroups++;

        prmxAddPortRuleUri(p->prmDstPort[ dport ], rd);
    }

    if ( sport != ANYPORT && sport < MAX_PORTS) /* src=ANY, SRC=80,21,25,etc. */
    {
        p->prmNumSrcRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmSrcPort[sport] == NULL)
        {
            p->prmSrcPort[sport] = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmSrcPort[sport] == NULL)
            {
                return 1;
            }
        }

        if (p->prmSrcPort[sport]->pgCount==0)
            p->prmNumSrcGroups++;

        prmxAddPortRuleUri(p->prmSrcPort[ sport ], rd);
    }

    if ( sport == ANYPORT && dport == ANYPORT) /* dst=ANY, src=ANY */
    {
        p->prmNumGenericRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmGeneric == NULL)
        {
            p->prmGeneric = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmGeneric == NULL)
            {
                return 1;
            }
        }

        prmxAddPortRuleUri(p->prmGeneric, rd);
    }

    return 0;
}

/*
**
**  NAME
**    prmAddRuleNC::
**
**  DESCRIPTION
**    This function adds a rule to a PORT_RULE_MAP.  Depending on the
**    values of the sport and dport, the rule gets added in different
**    groups (src,dst,generic).  The values for dport and sport
**    can be: 0 -> 64K or -1 for generic (meaning that the rule applies
**    to all values.
**
**    Warning: Consider this carefully.
**    Some rules use 6000:6005 -> any  for a port designation, we could
**    add each rule to it's own group, in this case Src=6000 to 6005.
**    But we opt to add them as ANY rules for now, to reduce groups.
**
**    IMPORTANT:
**    This function adds a rule to the "no content" list of rules.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to add rule to.
**    int - the dst port value.
**    int - the src port value.
**    RULE_PTR - the ptr to the user data for the rule.
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure.
**
*/
int prmAddRuleNC(PORT_RULE_MAP* p, int dport, int sport, RULE_PTR rd)
{
    if ( dport != ANYPORT && dport < MAX_PORTS )  /* dst=21,25,80,110,139 */
    {
        p->prmNumDstRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmDstPort[dport] == NULL)
        {
            p->prmDstPort[dport] = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmDstPort[dport] == NULL)
            {
                return 1;
            }
        }

        if (p->prmDstPort[dport]->pgCount==0)
            p->prmNumDstGroups++;

        prmxAddPortRuleNC(p->prmDstPort[ dport ], rd);
    }

    if ( sport != ANYPORT && sport < MAX_PORTS) /* src=ANY, SRC=80,21,25,etc. */
    {
        p->prmNumSrcRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmSrcPort[sport] == NULL)
        {
            p->prmSrcPort[sport] = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmSrcPort[sport] == NULL)
            {
                return 1;
            }
        }

        if (p->prmSrcPort[sport]->pgCount==0)
            p->prmNumSrcGroups++;

        prmxAddPortRuleNC(p->prmSrcPort[ sport ], rd);
    }

    if ( sport == ANYPORT && dport == ANYPORT) /* dst=ANY, src=ANY */
    {
        p->prmNumGenericRules++;

        /*
        **  Check to see if this PORT_GROUP has been initialized
        */
        if (p->prmGeneric == NULL)
        {
            p->prmGeneric = (PORT_GROUP*)calloc(1, sizeof(PORT_GROUP));
            if (p->prmGeneric == NULL)
            {
                return 1;
            }
        }

        prmxAddPortRuleNC(p->prmGeneric, rd);
    }

    return 0;
}

int prmAddByteRuleNC(BYTE_RULE_MAP* p, int dport, RULE_PTR rd)
{
    if ( dport != ANYPORT && dport < 256 )  /* dst=21,25,80,110,139 */
    {
        p->prmNumRules++;
        if (p->prmByteGroup[dport].pgCount==0)
            p->prmNumGroups++;

        prmxAddPortRuleNC(&(p->prmByteGroup[ dport ]), rd);
    }
    else if ( dport == ANYPORT) /* dst=ANY, src=ANY */
    {
        p->prmNumGenericRules++;

        prmxAddPortRuleNC(&(p->prmGeneric), rd);
    }

    return 0;
}

/*
**
**  NAME
**    prmFindRuleGroup::
**
**  DESCRIPTION
**    Given a PORT_RULE_MAP, this function selects the PORT_GROUP or
**    PORT_GROUPs necessary to fully match a given dport, sport pair.
**    The selection logic looks at both the dport and sport and
**    determines if one or both are unique.  If one is unique, then
**    the appropriate PORT_GROUP ptr is set.  If both are unique, then
**    both th src and dst PORT_GROUP ptrs are set.  If neither of the
**    ports are unique, then the gen PORT_GROUP ptr is set.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the PORT_RULE_MAP to pick PORT_GROUPs from.
**    int             - the dst port value (0->64K or -1 for generic)
**    int             - the src port value (0->64K or -1 for generic)
**    PORT_GROUP **   - the src PORT_GROUP ptr to set.
**    PORT_GROUP **   - the dst PORT_GROUP ptr to set.
**    PORT_GROUP **   - the generic PORT_GROUP ptr to set.
**
**  FORMAL OUTPUT
**    int -  0: Don't evaluate
**           1: There are port groups to evaluate
**
**  NOTES
**    Currently, if there is a "unique conflict", we return both the src
**    and dst PORT_GROUPs.  This conflict forces us to do two searches, one
**    for the src and one for the dst.  So we are taking twice the time to
**    inspect a packet then usual.  Obviously, this is not good.  There
**    are several options that we have to deal with unique conflicts, but
**    have not implemented any currently.  The optimum solution will be to
**    incorporate streaming and protocol analysis to a session so we know
**    what to match against.
**
*/
int prmFindRuleGroup(
    PORT_RULE_MAP* p,
    int dport,
    int sport,
    PORT_GROUP** src,
    PORT_GROUP** dst,
    PORT_GROUP** gen
    )
{
    if ((p == NULL) || (src == NULL)
        || (dst == NULL) || (gen == NULL))
    {
        return 0;
    }

    *src = NULL;
    *dst = NULL;
    *gen = NULL;

    if ((dport != ANYPORT) && (dport < MAX_PORTS))
        *dst = p->prmDstPort[dport];

    if ((sport != ANYPORT) && (sport < MAX_PORTS))
        *src = p->prmSrcPort[sport];

    /* If no Src/Dst rules - use the generic set, if any exist  */
    if ((p->prmGeneric != NULL) && (p->prmGeneric->pgCount > 0))
    {
        if (fpDetectSplitAnyAny(snort_conf->fast_pattern_config)
            || ((*src == NULL) && (*dst == NULL)))
        {
            *gen = p->prmGeneric;
        }
    }

    if ((*src == NULL) && (*dst == NULL) && (*gen == NULL))
        return 0;

    return 1;
}

int prmFindGenericRuleGroup(PORT_RULE_MAP* p, PORT_GROUP** gen)
{
    if (gen == NULL)
    {
        return 0;
    }

    *gen = NULL;
    if ((p->prmGeneric != NULL) && (p->prmGeneric->pgCount > 0))
    {
        if (fpDetectSplitAnyAny(snort_conf->fast_pattern_config))
        {
            *gen = p->prmGeneric;
            return 1;
        }
    }
    return 0;
}

/*
*
*/
int prmFindByteRuleGroup(BYTE_RULE_MAP* p, int dport, PORT_GROUP** dst, PORT_GROUP** gen)
{
    int stat= 0;

    if ( (dport != ANYPORT && dport < 256 ) && p->prmByteGroup[dport].pgCount  )
    {
        *dst  = &p->prmByteGroup[dport];
        stat = 1;
    }
    else
    {
        *dst=0;
    }

    /* If no Src/Dst rules - use the generic set, if any exist  */
    if ( !stat &&  (p->prmGeneric.pgCount > 0) )
    {
        *gen  = &p->prmGeneric;
        stat = 4;
    }
    else
    {
        *gen = 0;
    }

    return stat;
}

/*
** Access each Rule group by index (0-MAX_PORTS)
*/
PORT_GROUP* prmFindDstRuleGroup(PORT_RULE_MAP* p, int port)
{
    if ( port < 0 || port >= MAX_PORTS )
        return 0;

    if ( p->prmDstPort[port])
        return p->prmDstPort[port];

    return 0;
}

/*
** Access each Rule group by index (0-MAX_PORTS)
*/
PORT_GROUP* prmFindSrcRuleGroup(PORT_RULE_MAP* p, int port)
{
    if ( port < 0 || port >= MAX_PORTS )
        return 0;

    if ( p->prmSrcPort[port])
        return p->prmSrcPort[port];

    return 0;
}

/*
**
**  NAME
**    prmCompileGroups::
**
**  DESCRIPTION
**    Add Generic rules to each Unique rule group, this could be
**    optimized a bit, right now we will process generic rules
**    twice when packets have 2 unique ports, but this will not
**    occur often.
**
**    The generic rules are added to the Unique rule groups, so that
**    the setwise methodology can be taking advantage of.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the PORT_RULE_MAP to compile generice rules.
**
**  FORMAL OUTPUT
**    int - 0 is successful;
**
*/
int prmCompileGroups(PORT_RULE_MAP* p)
{
    PORT_GROUP* pgGen, * pgSrc, * pgDst;
    RULE_PTR* prule;
    int i;

    /*
    **  Add Generic to Src and Dst groups
    */
    pgGen = p->prmGeneric;

    if (!pgGen)
        return 0;

    for (i=0; i<MAX_PORTS; i++)
    {
        /* Add to the Unique Src and Dst Groups as well,
        ** but don't inc thier prmNUMxxx counts, we want these to be true Unique counts
        ** we can add the Generic numbers if we want these, besides
        ** each group has it's own count.
        */

        if (p->prmSrcPort[i])
        {
            pgSrc = p->prmSrcPort[i];

            prule = (RULE_PTR*)prmGetFirstRule(pgGen);
            while ( prule )
            {
                prmxAddPortRule(pgSrc, prule);
                prule = (RULE_PTR*)prmGetNextRule(pgGen);
            }

            prule = (RULE_PTR*)prmGetFirstRuleUri(pgGen);
            while ( prule )
            {
                prmxAddPortRuleUri(pgSrc, prule);
                prule = (RULE_PTR*)prmGetNextRuleUri(pgGen);
            }

            prule = (RULE_PTR*)prmGetFirstRuleNC(pgGen);
            while ( prule )
            {
                prmxAddPortRuleNC(pgSrc, prule);
                prule = (RULE_PTR*)prmGetNextRuleNC(pgGen);
            }
        }

        if (p->prmDstPort[i])
        {
            pgDst = p->prmDstPort[i];

            prule = (RULE_PTR*)prmGetFirstRule(pgGen);
            while ( prule )
            {
                prmxAddPortRule(pgDst, prule);
                prule = (RULE_PTR*)prmGetNextRule(pgGen);
            }

            prule = (RULE_PTR*)prmGetFirstRuleUri(pgGen);
            while ( prule )
            {
                prmxAddPortRuleUri(pgDst, prule);
                prule = (RULE_PTR*)prmGetNextRuleUri(pgGen);
            }

            prule = (RULE_PTR*)prmGetFirstRuleNC(pgGen);
            while ( prule )
            {
                prmxAddPortRuleNC(pgDst, prule);
                prule = (RULE_PTR*)prmGetNextRuleNC(pgGen);
            }
        }
    }

    return 0;
}

/*
*
*
*/
int prmCompileByteGroups(BYTE_RULE_MAP* p)
{
    PORT_GROUP* pgGen, * pgByte;
    RULE_PTR* prule;
    int i;

    /*
    **  Add Generic to Unique groups
    */
    pgGen = &p->prmGeneric;

    if ( !pgGen->pgCount )
        return 0;

    for (i=0; i<256; i++)
    {
        if (p->prmByteGroup[i].pgCount)
        {
            pgByte = &p->prmByteGroup[i];

            prule = (RULE_PTR*)prmGetFirstRule(pgGen);
            while ( prule )
            {
                prmxAddPortRule(pgByte, prule);
                prule = (RULE_PTR*)prmGetNextRule(pgGen);
            }

            prule = (RULE_PTR*)prmGetFirstRuleNC(pgGen);
            while ( prule )
            {
                prmxAddPortRuleNC(pgByte, prule);
                prule = (RULE_PTR*)prmGetNextRuleNC(pgGen);
            }
        }
    }

    return 0;
}

/*
**
**  NAME
**    prmShowStats::
**
**  DESCRIPTION
**    This function shows some basic stats on the fast packet
**    classification.  It show the the number of PORT_GROUPS
**    for a PORT_RULE_MAP, and the break down of the different
**    rule types (content, uri, no content).
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the PORT_RULE_MAP to show stats on.
**
**  FORMAL OUTPUT
**    int - 0 is successful.
**
*/
int prmShowStats(PORT_RULE_MAP* p)
{
    int i;
    PORT_GROUP* pg;

    LogMessage("Packet Classification Rule Manager Stats ----\n");
    LogMessage("NumDstGroups   : %d\n",p->prmNumDstGroups);
    LogMessage("NumSrcGroups   : %d\n",p->prmNumSrcGroups);
    LogMessage("\n");
    LogMessage("NumDstRules    : %d\n",p->prmNumDstRules);
    LogMessage("NumSrcRules    : %d\n",p->prmNumSrcRules);
    LogMessage("NumGenericRules: %d\n",p->prmNumGenericRules);
    LogMessage("\n");

    LogMessage("%d Dst Groups In Use, %d Unique Rules, includes generic\n",p->prmNumDstGroups,
        p->prmNumDstRules);
    for (i=0; i<MAX_PORTS; i++)
    {
        pg = prmFindDstRuleGroup(p, i);
        if (pg)
        {
            LogMessage("  Dst Port %5d : %d uricontent, %d content, %d nocontent \n",i,
                pg->pgUriContentCount,pg->pgContentCount,pg->pgNoContentCount);
            if ( pg->avgLen )
            {
                LogMessage("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
                if (pg->c1)
                    LogMessage(" [1]=%d",pg->c1);
                if (pg->c2)
                    LogMessage(" [2]=%d",pg->c2);
                if (pg->c3)
                    LogMessage(" [3]=%d",pg->c3);
                if (pg->c4)
                    LogMessage(" [4]=%d",pg->c4);
                LogMessage("\n");
            }
        }
    }

    LogMessage("%d Src Groups In Use, %d Unique Rules, includes generic\n",p->prmNumSrcGroups,
        p->prmNumSrcRules);
    for (i=0; i<MAX_PORTS; i++)
    {
        pg = prmFindSrcRuleGroup(p, i);
        if (pg)
        {
            LogMessage("  Src Port %5d : %d uricontent, %d content, %d nocontent \n",i,
                pg->pgUriContentCount,pg->pgContentCount,pg->pgNoContentCount);
            if ( pg->avgLen )
            {
                LogMessage("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
                if (pg->c1)
                    LogMessage(" [1]=%d",pg->c1);
                if (pg->c2)
                    LogMessage(" [2]=%d",pg->c2);
                if (pg->c3)
                    LogMessage(" [3]=%d",pg->c3);
                if (pg->c4)
                    LogMessage(" [4]=%d",pg->c4);
                LogMessage("\n");
            }
        }
    }

    pg = p->prmGeneric;
    if (pg)
    {
        LogMessage("   Generic Rules : %d uricontent, %d content, %d nocontent \n",
            pg->pgUriContentCount,pg->pgContentCount,pg->pgNoContentCount);
        if ( pg->avgLen )
        {
            LogMessage("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
            if (pg->c1)
                LogMessage(" [1]=%d",pg->c1);
            if (pg->c2)
                LogMessage(" [2]=%d",pg->c2);
            if (pg->c3)
                LogMessage(" [3]=%d",pg->c3);
            if (pg->c4)
                LogMessage(" [4]=%d",pg->c4);
            LogMessage("\n");
        }
    }

    return 0;
}

/*
**
**  NAME
**    prmShowEventStats::
**
**  DESCRIPTION
**    This function is used at the close of the Fast Packet
**    inspection.  It tells how many non-qualified and qualified
**    hits occurred for each PORT_GROUP.  A non-qualified hit
**    is defined by an initial match against a packet, but upon
**    further inspection a hit was not validated.  Non-qualified
**    hits occur because we can match on the most unique aspect
**    of a packet, this is the content.  Snort has other flags
**    then content though, so once we hit a content match we must
**    verify these additional flags.  Sometimes these flags do
**    not pass the validation.  A qualified hit is an event that
**    has been fully qualified, and has been put in the event
**    cache for event selection.  Qualified hits are not a subset
**    of non-qualified hits.  Ideally, non-qualified hits should
**    be zero.  The reason for these stats is that it allows
**    users to trouble shoot PORT_GROUPs.  A poorly written rule
**    may cause many non-qualified events, and these stats
**    allow the user to track this down.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * -  the PORT_RULE_MAP to show stats on.
**
**  FORMAL OUTPUT
**    int - 0 is successful.
**
*/
int prmShowEventStats(PORT_RULE_MAP* p)
{
    int i;
    PORT_GROUP* pg;

    int NQEvents = 0;
    int QEvents = 0;

    LogMessage("Packet Classification Rule Manager Stats ----\n");
    LogMessage("NumDstGroups   : %d\n",p->prmNumDstGroups);
    LogMessage("NumSrcGroups   : %d\n",p->prmNumSrcGroups);
    LogMessage("\n");
    LogMessage("NumDstRules    : %d\n",p->prmNumDstRules);
    LogMessage("NumSrcRules    : %d\n",p->prmNumSrcRules);
    LogMessage("NumGenericRules: %d\n",p->prmNumGenericRules);
    LogMessage("\n");

    LogMessage("%d Dst Groups In Use, %d Unique Rules, includes generic\n",p->prmNumDstGroups,
        p->prmNumDstRules);
    for (i=0; i<MAX_PORTS; i++)
    {
        pg = prmFindDstRuleGroup(p, i);
        if (pg)
        {
            NQEvents += pg->pgNQEvents;
            QEvents  += pg->pgQEvents;

            if ( pg->pgNQEvents + pg->pgQEvents )
            {
                LogMessage("  Dst Port %5d : %d group entries \n",i, pg->pgCount);
                LogMessage("    NQ Events  : %d\n", pg->pgNQEvents);
                LogMessage("     Q Events  : %d\n", pg->pgQEvents);
            }
        }
    }

    LogMessage("%d Src Groups In Use, %d Unique Rules, includes generic\n",p->prmNumSrcGroups,
        p->prmNumSrcRules);
    for (i=0; i<MAX_PORTS; i++)
    {
        pg = prmFindSrcRuleGroup(p, i);
        if (pg)
        {
            NQEvents += pg->pgNQEvents;
            QEvents += pg->pgQEvents;

            if ( pg->pgNQEvents + pg->pgQEvents )
            {
                LogMessage("  Src Port %5d : %d group entries \n",i, pg->pgCount);
                LogMessage("    NQ Events  : %d\n", pg->pgNQEvents);
                LogMessage("     Q Events  : %d\n", pg->pgQEvents);
            }
        }
    }

    pg = p->prmGeneric;
    if (pg)
    {
        NQEvents += pg->pgNQEvents;
        QEvents += pg->pgQEvents;

        if ( pg->pgNQEvents + pg->pgQEvents )
        {
            LogMessage("  Generic Rules : %d group entries\n", pg->pgCount);
            LogMessage("    NQ Events   : %d\n", pg->pgNQEvents);
            LogMessage("     Q Events   : %d\n", pg->pgQEvents);
        }
    }

    LogMessage("Total NQ Events : %d\n", NQEvents);
    LogMessage("Total  Q Events  : %d\n", QEvents);

    return 0;
}

