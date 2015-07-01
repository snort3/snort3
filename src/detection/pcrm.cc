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
**   PortGroup  *src, *dst, *generic;
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
#include "fp_config.h"
#include "fp_create.h"
#include "snort_config.h"

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
**    prmFindRuleGroup::
**
**  DESCRIPTION
**    Given a PORT_RULE_MAP, this function selects the PortGroup or
**    PortGroups necessary to fully match a given dport, sport pair.
**    The selection logic looks at both the dport and sport and
**    determines if one or both are unique.  If one is unique, then
**    the appropriate PortGroup ptr is set.  If both are unique, then
**    both th src and dst PortGroup ptrs are set.  If neither of the
**    ports are unique, then the gen PortGroup ptr is set.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the PORT_RULE_MAP to pick PortGroups from.
**    int             - the dst port value (0->64K or -1 for generic)
**    int             - the src port value (0->64K or -1 for generic)
**    PortGroup **   - the src PortGroup ptr to set.
**    PortGroup **   - the dst PortGroup ptr to set.
**    PortGroup **   - the generic PortGroup ptr to set.
**
**  FORMAL OUTPUT
**    int -  0: Don't evaluate
**           1: There are port groups to evaluate
**
**  NOTES
**    Currently, if there is a "unique conflict", we return both the src
**    and dst PortGroups.  This conflict forces us to do two searches, one
**    for the src and one for the dst.  So we are taking twice the time to
**    inspect a packet then usual.  Obviously, this is not good.  There
**    are several options that we have to deal with unique conflicts, but
**    have not implemented any currently.  The optimum solution will be to
**    incorporate streaming and protocol analysis to a session so we know
**    what to match against.
**
*/
static int prmFindRuleGroup(
    PORT_RULE_MAP* p,
    int dport,
    int sport,
    PortGroup** src,
    PortGroup** dst,
    PortGroup** gen
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
    if ((p->prmGeneric != NULL) && (p->prmGeneric->rule_count > 0))
    {
        if (snort_conf->fast_pattern_config->get_split_any_any()
            || ((*src == NULL) && (*dst == NULL)))
        {
            *gen = p->prmGeneric;
        }
    }

    if ((*src == NULL) && (*dst == NULL) && (*gen == NULL))
        return 0;

    return 1;
}

/*
**  The following functions are wrappers to the pcrm routines,
**  that utilize the variables that we have intialized by
**  calling fpCreateFastPacketDetection().  These functions
**  are also used in the file fpdetect.c, where we do lookups
**  on the initialized variables.
*/
int prmFindRuleGroupIp(PORT_RULE_MAP* prm, int ip_proto, PortGroup** ip_group, PortGroup** gen)
{
    PortGroup* src;
    return prmFindRuleGroup(prm, ip_proto, ANYPORT, &src, ip_group, gen);
}

int prmFindRuleGroupIcmp(PORT_RULE_MAP* prm, int type, PortGroup** type_group, PortGroup** gen)
{
    PortGroup* src;
    return prmFindRuleGroup(prm, type, ANYPORT, &src, type_group, gen);
}

int prmFindRuleGroupTcp(PORT_RULE_MAP* prm, int dport, int sport, PortGroup** src,
    PortGroup** dst, PortGroup** gen)
{
    return prmFindRuleGroup(prm, dport, sport, src, dst, gen);
}

int prmFindRuleGroupUdp(PORT_RULE_MAP* prm, int dport, int sport, PortGroup** src,
    PortGroup** dst, PortGroup** gen)
{
    return prmFindRuleGroup(prm, dport, sport, src, dst, gen);
}

int prmFindGenericRuleGroup(PORT_RULE_MAP* p, PortGroup** gen)
{
    if ( !p or !gen )
    {
        return 0;
    }

    *gen = NULL;
    if ((p->prmGeneric != NULL) && (p->prmGeneric->rule_count > 0))
    {
        if (snort_conf->fast_pattern_config->get_split_any_any())
        {
            *gen = p->prmGeneric;
            return 1;
        }
    }
    return 0;
}

/*
** Access each Rule group by index (0-MAX_PORTS)
*/
static PortGroup* prmFindDstRuleGroup(PORT_RULE_MAP* p, int port)
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
static PortGroup* prmFindSrcRuleGroup(PORT_RULE_MAP* p, int port)
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
**    prmShowEventStats::
**
**  DESCRIPTION
**    This function is used at the close of the Fast Packet
**    inspection.  It tells how many non-qualified and qualified
**    hits occurred for each PortGroup.  A non-qualified hit
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
**    users to trouble shoot PortGroups.  A poorly written rule
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
    PortGroup* pg;

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
            NQEvents += pg->match_count;
            QEvents  += pg->event_count;

            if ( pg->match_count + pg->event_count )
            {
                LogMessage("  Dst Port %5d : %d group entries \n",i, pg->rule_count);
                LogMessage("    NQ Events  : %d\n", pg->match_count);
                LogMessage("     Q Events  : %d\n", pg->event_count);
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
            NQEvents += pg->match_count;
            QEvents += pg->event_count;

            if ( pg->match_count + pg->event_count )
            {
                LogMessage("  Src Port %5d : %d group entries \n",i, pg->rule_count);
                LogMessage("    NQ Events  : %d\n", pg->match_count);
                LogMessage("     Q Events  : %d\n", pg->event_count);
            }
        }
    }

    pg = p->prmGeneric;
    if (pg)
    {
        NQEvents += pg->match_count;
        QEvents += pg->event_count;

        if ( pg->match_count + pg->event_count )
        {
            LogMessage("  Generic Rules : %d group entries\n", pg->rule_count);
            LogMessage("    NQ Events   : %d\n", pg->match_count);
            LogMessage("     Q Events   : %d\n", pg->event_count);
        }
    }

    LogMessage("Total NQ Events : %d\n", NQEvents);
    LogMessage("Total  Q Events  : %d\n", QEvents);

    return 0;
}

