//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
**  --------------------------------------------------------------------------
**  Marc Norton <mnorton@sourcefire.com>
**  Dan Roelker <droelker@sourcefire.com>
**
**  NOTES
**  5.15.02   - Initial version of pcrm.c distributed. - Norton/Roelker
**
**  Packet Classification and Rule Manager
**
**  A Fast Packet Classification method for Rule and Pattern Matching in SNORT
**  --------------------------------------------------------------------------
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcrm.h"

#include "main/snort_config.h"
#include "utils/util.h"

#include "fp_config.h"

PORT_RULE_MAP* prmNewMap()
{
    PORT_RULE_MAP* p = (PORT_RULE_MAP*)snort_calloc(sizeof(PORT_RULE_MAP));
    return p;
}

/*
**  DESCRIPTION
**    Given a PORT_RULE_MAP, this function selects the PortGroup or
**    PortGroups necessary to fully match a given dport, sport pair.
**    The selection logic looks at both the dport and sport and
**    determines if one or both are unique.  If one is unique, then
**    the appropriate PortGroup ptr is set.  If both are unique, then
**    both th src and dst PortGroup ptrs are set.  If neither of the
**    ports are unique, then the gen PortGroup ptr is set.
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
    if ( !p )
        return 0;

    assert(src and dst and gen);
    *src = *dst = *gen = nullptr;

    if ( (dport != ANYPORT) and (dport < snort::MAX_PORTS) )
        *dst = p->prmDstPort[dport];

    if ( (sport != ANYPORT) and (sport < snort::MAX_PORTS) )
        *src = p->prmSrcPort[sport];

    /* If no Src/Dst rules - use the generic set, if any exist  */
    if ( p->prmGeneric and (p->prmGeneric->rule_count > 0) )
    {
        if ( snort::SnortConfig::get_conf()->fast_pattern_config->get_split_any_any() or (!*src and !*dst) )
        {
            *gen = p->prmGeneric;
        }
    }

    if ( *src or *dst or *gen )
        return 1;

    return 0;
}

/*
**  The following functions are wrappers to the pcrm routines,
**  that utilize the variables that we have initialized by
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

