//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "parse_rule.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <pcap.h>
#include <grp.h>
#include <pwd.h>
#include <fnmatch.h>

#include "parser.h"
#include "cmd_line.h"
#include "config_file.h"
#include "parse_conf.h"
#include "parse_ports.h"

#include "detection/rules.h"
#include "detection/treenodes.h"
#include "detection/detect.h"
#include "detection/tag.h"
#include "detection/signature.h"
#include "detection/fp_config.h"
#include "detection/fp_create.h"
#include "detection/pattern_match_data.h"
#include "detection/sfrim.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "ports/port_object.h"
#include "ports/rule_port_tables.h"
#include "protocols/packet.h"
#include "filters/sfthreshold.h"
#include "filters/sfthd.h"
#include "hash/sfghash.h"
#include "sfip/sf_vartable.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_ipvar.h"
#include "utils/sflsq.h"
#include "utils/util.h"
#include "filters/rate_filter.h"
#include "filters/detection_filter.h"
#include "packet_io/active.h"
#include "file_api/file_config.h"
#include "framework/ips_option.h"
#include "managers/ips_manager.h"
#include "managers/so_manager.h"
#include "target_based/snort_protocols.h"

#define RULE_DIR_OPT__DIRECTIONAL    "->"
#define RULE_DIR_OPT__BIDIRECTIONAL  "<>"

#define SRC  0
#define DST  1

/* rule counts for port lists */
struct rule_count_t
{
    int src;
    int dst;
    int any;  /* any-any */
    int both;  /* src+dst ports specified */
    int nfp;  /* no content */
};

static int rule_count = 0;
static int detect_rule_count = 0;
static int builtin_rule_count = 0;
static int so_rule_count = 0;
static int head_count = 0;          /* number of header blocks (chain heads?) */
static int otn_count = 0;           /* number of chains */
static int rule_proto = 0;

static rule_count_t tcpCnt;
static rule_count_t udpCnt;
static rule_count_t icmpCnt;
static rule_count_t ipCnt;
static rule_count_t svcCnt;  // dummy for now

static bool s_ignore = false;  // for skipping drop rules when not inline, etc.

/*
 * Finish adding the rule to the port tables
 *
 * 1) find the table this rule should belong to (src/dst/any-any tcp,udp,icmp,ip or nocontent)
 * 2) find an index for the sid:gid pair
 * 3) add all no content rules to a single no content port object, the ports are irrelevant so
 *    make it a any-any port object.
 * 4) if it's an any-any rule with content, add to an any-any port object
 * 5) find if we have a port object with these ports defined, if so get it, otherwise create it.
 *    a)do this for src and dst port
 *    b)add the rule index/id to the portobject(s)
 *    c)if the rule is bidir add the rule and port-object to both src and dst tables
 */
static int FinishPortListRule(
    RulePortTables* port_tables, RuleTreeNode* rtn, OptTreeNode* otn,
    int proto, bool has_fp, FastPatternConfig* fp)
{
    int large_port_group = 0;
    int src_cnt = 0;
    int dst_cnt = 0;
    int rim_index;
    PortTable* dstTable;
    PortTable* srcTable;
    PortObject* aaObject;
    rule_count_t* prc;
    uint32_t orig_flags = rtn->flags;

    assert(otn->proto == proto);

    /* Select the Target PortTable for this rule, based on protocol, src/dst
     * dir, and if there is rule content */
    switch ( proto )
    {
    case SNORT_PROTO_IP:
        dstTable = port_tables->ip.dst;
        srcTable = port_tables->ip.src;
        aaObject = port_tables->ip.any;
        prc = &ipCnt;
        break;

    case SNORT_PROTO_ICMP:
        dstTable = port_tables->icmp.dst;
        srcTable = port_tables->icmp.src;
        aaObject = port_tables->icmp.any;
        prc = &icmpCnt;
        break;

    case SNORT_PROTO_TCP:
        dstTable = port_tables->tcp.dst;
        srcTable = port_tables->tcp.src;
        aaObject = port_tables->tcp.any;
        prc = &tcpCnt;
        break;

    case SNORT_PROTO_UDP:
        dstTable = port_tables->udp.dst;
        srcTable = port_tables->udp.src;
        aaObject = port_tables->udp.any;
        prc = &udpCnt;
        break;

    default:
        rtn->flags |= ANY_SRC_PORT|ANY_DST_PORT;
        dstTable = srcTable = nullptr;
        aaObject = port_tables->svc_any;
        prc = &svcCnt;
    }

    /* Count rules with both src and dst specific ports */
    if (!(rtn->flags & ANY_DST_PORT) && !(rtn->flags & ANY_SRC_PORT))
    {
        DebugFormat(DEBUG_PORTLISTS,
            "***\n***Info:  src & dst ports are both specific"
            " >> gid=%u sid=%u\n***\n",
            otn->sigInfo.generator, otn->sigInfo.id);

        prc->both++;
    }

    /* Create/find an index to store this rules sid and gid at,
     * and use as reference in Port Objects */
    rim_index = otn->ruleIndex;

    /* Add up the nfp rules */
    if ( !has_fp )
        prc->nfp++;

    /* If not an any-any rule test for port bleedover, if we are using a
     * single rule group, don't bother */
    if (!fp->get_single_rule_group() &&
        (rtn->flags & (ANY_DST_PORT|ANY_SRC_PORT)) != (ANY_DST_PORT|ANY_SRC_PORT))
    {
        if (!(rtn->flags & ANY_SRC_PORT))
        {
            src_cnt = PortObjectPortCount(rtn->src_portobject);
            if (src_cnt >= fp->get_bleed_over_port_limit())
                large_port_group = 1;
        }

        if (!(rtn->flags & ANY_DST_PORT))
        {
            dst_cnt = PortObjectPortCount(rtn->dst_portobject);
            if (dst_cnt >= fp->get_bleed_over_port_limit())
                large_port_group = 1;
        }

        if (large_port_group && fp->get_bleed_over_warnings())
        {
            LogMessage("***Bleedover Port Limit(%d) Exceeded for rule %u:%u "
                "(%d)ports: ", fp->get_bleed_over_port_limit(),
                otn->sigInfo.generator, otn->sigInfo.id,
                (src_cnt > dst_cnt) ? src_cnt : dst_cnt);

            /* If logging to syslog, this will be all multiline */
            fflush(stdout); fflush(stderr);
            PortObjectPrintPortsRaw(rtn->src_portobject);
            LogMessage(" -> ");
            PortObjectPrintPortsRaw(rtn->dst_portobject);
            LogMessage(" adding to any-any group\n");
            fflush(stdout); fflush(stderr);
        }
    }

    /* If an any-any rule add rule index to any-any port object
     * both content and no-content type rules go here if they are
     * any-any port rules...
     * If we have an any-any rule or a large port group or
     * were using a single rule group we make it an any-any rule. */
    if (((rtn->flags & (ANY_DST_PORT|ANY_SRC_PORT)) == (ANY_DST_PORT|ANY_SRC_PORT)) ||
        large_port_group || fp->get_single_rule_group())
    {
        if (proto == SNORT_PROTO_IP)
        {
            /* Add the IP rules to the higher level app protocol groups, if they apply
             * to those protocols.  All IP rules should have any-any port descriptors
             * and fall into this test.  IP rules that are not tcp/udp/icmp go only into the
             * IP table */
            DebugFormat(DEBUG_PORTLISTS,
                "Finishing IP any-any rule %u:%u\n",
                otn->sigInfo.generator,otn->sigInfo.id);

            switch ( otn->proto )
            {
            case SNORT_PROTO_IP:    /* Add to all ip proto any port tables */
                PortObjectAddRule(port_tables->icmp.any, rim_index);
                icmpCnt.any++;

                PortObjectAddRule(port_tables->tcp.any, rim_index);
                tcpCnt.any++;

                PortObjectAddRule(port_tables->udp.any, rim_index);
                udpCnt.any++;
                break;

            case SNORT_PROTO_ICMP:
                PortObjectAddRule(port_tables->icmp.any, rim_index);
                icmpCnt.any++;
                break;

            case SNORT_PROTO_TCP:
                PortObjectAddRule(port_tables->tcp.any, rim_index);
                tcpCnt.any++;
                break;

            case SNORT_PROTO_UDP:
                PortObjectAddRule(port_tables->udp.any, rim_index);
                udpCnt.any++;
                break;

            default:
                break;
            }
        }
        /* For all protocols-add to the any any group */
        PortObjectAddRule(aaObject, rim_index);
        prc->any++;
        rtn->flags = orig_flags;
        return 0; /* done */
    }

    /* add rule index to dst table if we have a specific dst port or port list */
    if (!(rtn->flags & ANY_DST_PORT))
    {
        PortObject* pox;

        prc->dst++;

        DebugMessage(DEBUG_PORTLISTS,
            "Finishing rule: dst port rule\n");

        /* find the proper port object */
        pox = PortTableFindInputPortObjectPorts(dstTable, rtn->dst_portobject);
        if (pox == NULL)
        {
            /* Create a permanent port object */
            pox = PortObjectDupPorts(rtn->dst_portobject);
            if (pox == NULL)
            {
                ParseError("could not dup a port object - out of memory.");
                return -1;
            }

            /* Add the port object to the table, and add the rule to the port object */
            PortTableAddObject(dstTable, pox);
        }

        PortObjectAddRule(pox, rim_index);

        /* if bidir, add this rule and port group to the src table */
        if (rtn->flags & BIDIRECTIONAL)
        {
            pox = PortTableFindInputPortObjectPorts(srcTable, rtn->dst_portobject);
            if (pox == NULL)
            {
                pox = PortObjectDupPorts(rtn->dst_portobject);
                if (pox == NULL)
                {
                    ParseError("could not dup a bidir-port object - out of memory.");
                    return -1;
                }

                PortTableAddObject(srcTable, pox);
            }

            PortObjectAddRule(pox, rim_index);
        }
    }

    /* add rule index to src table if we have a specific src port or port list */
    if (!(rtn->flags & ANY_SRC_PORT))
    {
        PortObject* pox;

        prc->src++;

        pox = PortTableFindInputPortObjectPorts(srcTable, rtn->src_portobject);
        if (pox == NULL)
        {
            pox = PortObjectDupPorts(rtn->src_portobject);
            if (pox == NULL)
            {
                ParseError("could not dup a port object - out of memory.");
                return -1;
            }

            PortTableAddObject(srcTable, pox);
        }

        PortObjectAddRule(pox, rim_index);

        /* if bidir, add this rule and port group to the dst table */
        if (rtn->flags & BIDIRECTIONAL)
        {
            pox = PortTableFindInputPortObjectPorts(dstTable, rtn->src_portobject);
            if (pox == NULL)
            {
                pox = PortObjectDupPorts(rtn->src_portobject);
                if (pox == NULL)
                {
                    ParseError("could not dup a bidir-port object - out of memory.");
                    return -1;
                }

                PortTableAddObject(dstTable, pox);
            }

            PortObjectAddRule(pox, rim_index);
        }
    }

    return 0;
}

static int ValidateIPList(sfip_var_t* addrset, const char* token)
{
    if (!addrset || !(addrset->head||addrset->neg_head))
    {
        ParseError("empty IP used either as source IP or as "
            "destination IP in a rule. IP list: %s.", token);
        return -1;
    }

    return 0;
}

static int ProcessIP(
    SnortConfig*, const char* addr, RuleTreeNode* rtn, int mode, int)
{
    vartable_t* ip_vartable = get_ips_policy()->ip_vartable;

    assert(rtn);
    /* If a rule has a variable in it, we want to copy that variable's
     * contents to the IP variable (IP list) stored with the rtn.
     * This code tries to look up the variable, and if found, will copy it
     * to the rtn->{sip,dip} */
    if (mode == SRC)
    {
        int ret;

        if (rtn->sip == NULL)
        {
            sfip_var_t* tmp = sfvt_lookup_var(ip_vartable, addr);
            if (tmp != NULL)
            {
                rtn->sip = sfvar_create_alias(tmp, tmp->name);
                if (rtn->sip == NULL)
                    ret = SFIP_FAILURE;
                else
                    ret = SFIP_SUCCESS;
            }
            else
            {
                rtn->sip = (sfip_var_t*)snort_calloc(sizeof(sfip_var_t));
                ret = sfvt_add_to_var(ip_vartable, rtn->sip, addr);
            }
        }
        else
        {
            ret = sfvt_add_to_var(ip_vartable, rtn->sip, addr);
        }

        /* The function sfvt_add_to_var adds 'addr' to the variable 'rtn->sip' */
        if (ret != SFIP_SUCCESS)
        {
            if (ret == SFIP_LOOKUP_FAILURE)
            {
                ParseError("Undefined variable in the string: %s.", addr);
                return -1;
            }
            else if (ret == SFIP_CONFLICT)
            {
                ParseError("Negated IP ranges that are more general than "
                    "non-negated ranges are not allowed. Consider "
                    "inverting the logic: %s.", addr);
                return -1;
            }
            else if (ret == SFIP_NOT_ANY)
            {
                ParseError("!any is not allowed: %s.", addr);
                return -1;
            }
            else
            {
                ParseError("Unable to process the IP address: %s.", addr);
                return -1;
            }
        }

        if (rtn->sip->head && rtn->sip->head->flags & SFIP_ANY)
        {
            rtn->flags |= ANY_SRC_IP;
        }
    }
    /* mode == DST */
    else
    {
        int ret;

        if (rtn->dip == NULL)
        {
            sfip_var_t* tmp = sfvt_lookup_var(ip_vartable, addr);
            if (tmp != NULL)
            {
                rtn->dip = sfvar_create_alias(tmp, tmp->name);
                if (rtn->dip == NULL)
                    ret = SFIP_FAILURE;
                else
                    ret = SFIP_SUCCESS;
            }
            else
            {
                rtn->dip = (sfip_var_t*)snort_calloc(sizeof(sfip_var_t));
                ret = sfvt_add_to_var(ip_vartable, rtn->dip, addr);
            }
        }
        else
        {
            ret = sfvt_add_to_var(ip_vartable, rtn->dip, addr);
        }

        if (ret != SFIP_SUCCESS)
        {
            if (ret == SFIP_LOOKUP_FAILURE)
            {
                ParseError("undefined variable in the string: %s.", addr);
                return -1;
            }
            else if (ret == SFIP_CONFLICT)
            {
                ParseError("negated IP ranges that are more general than "
                    "non-negated ranges are not allowed. Consider "
                    "inverting the logic: %s.", addr);
                return -1;
            }
            else if (ret == SFIP_NOT_ANY)
            {
                ParseError("!any is not allowed: %s.", addr);
                return -1;
            }
            else
            {
                ParseError("unable to process the IP address: %s.", addr);
                return -1;
            }
        }

        if (rtn->dip->head && rtn->dip->head->flags & SFIP_ANY)
        {
            rtn->flags |= ANY_DST_IP;
        }
    }

    /* Make sure the IP lists provided by the user are valid */
    if (mode == SRC)
        ValidateIPList(rtn->sip, addr);
    else
        ValidateIPList(rtn->dip, addr);

    return 0;
}

/*
*  Parse a port string as a port var, and create or find a port object for it,
*  and add it to the port var table. These are used by the rtn's
*  as src and dst port lists for final rtn/otn processing.
*
*  These should not be confused with the port objects used to merge ports and rules
*  to build port group objects. Those are generated after the otn processing.
*
*/
static PortObject* ParsePortListTcpUdpPort(
    PortVarTable* pvt, PortTable* noname, const char* port_str)
{
    PortObject* portobject;
    POParser poparser;

    if ((pvt == NULL) || (noname == NULL) || (port_str == NULL))
        return NULL;

    /* 1st - check if we have an any port */
    if ( strcasecmp(port_str,"any")== 0 )
    {
        portobject = PortVarTableFind(pvt, "any");
        if (portobject == NULL)
            ParseAbort("PortVarTable missing an 'any' variable.");

        return portobject;
    }
    /* 2nd - check if we have a PortVar */
    else if ( port_str[0]=='$' )
    {
        /*||isalpha(port_str[0])*/ /*TODO: interferes with protocol names for ports*/
        const char* name = port_str + 1;

        DebugFormat(DEBUG_PORTLISTS,"PortVarTableFind: finding '%s'\n", port_str);

        /* look it up  in the port var table */
        portobject = PortVarTableFind(pvt, name);
        if (portobject == NULL)
            ParseAbort("***PortVar Lookup failed on '%s'.", port_str);

        DebugFormat(DEBUG_PORTLISTS,"PortVarTableFind: '%s' found!\n", port_str);
    }
    /* 3rd -  and finally process a raw port list */
    else
    {
        /* port list = [p,p,p:p,p,...] or p or p:p , no embedded spaces due to tokenizer */
        PortObject* pox;

        DebugFormat(DEBUG_PORTLISTS,
            "parser.c->PortObjectParseString: parsing '%s'\n",port_str);

        portobject = PortObjectParseString(pvt, &poparser, 0, port_str, 0);

        DebugFormat(DEBUG_PORTLISTS,
            "parser.c->PortObjectParseString: '%s' done.\n",port_str);

        if ( !portobject )
        {
            const char* errstr = PortObjectParseError(&poparser);
            ParseAbort("***Rule--PortVar Parse error: (pos=%d,error=%s)\n>>%s\n>>%*s",
                poparser.pos,errstr,port_str,poparser.pos,"^");
        }

        /* check if we already have this port object in the un-named port var table  ... */
        pox = PortTableFindInputPortObjectPorts(noname, portobject);
        if ( pox )
        {
            DebugFormat(DEBUG_PORTLISTS,
                "parser.c: already have '%s' as a PortObject - "
                "calling PortObjectFree(portbject) line=%d\n",port_str,__LINE__);
            PortObjectFree(portobject);
            portobject = pox;
        }
        else
        {
            DebugFormat(DEBUG_PORTLISTS,
                "parser.c: adding '%s' as a PortObject line=%d\n",port_str,__LINE__);
            /* Add to the un-named port var table */
            if (PortTableAddObject(noname, portobject))
            {
                ParseAbort("Unable to add raw port object to unnamed "
                    "port var table, out of memory.");
            }
        }
    }

    return portobject;
}

/*
 *   Process the rule, add it to the appropriate PortObject
 *   and add the PortObject to the rtn.
 *
 *   TCP/UDP rules use ports/portlists, icmp uses the icmp type field and ip uses the protocol
 *   field as a dst port for the purposes of looking up a rule group as packets are being
 *   processed.
 *
 *   TCP/UDP- use src/dst ports
 *   ICMP   - use icmp type as dst port,src=-1
 *   IP     - use protocol as dst port,src=-1
 *
 *   rtn - proto_node
 *   port_str - port list string or port var name
 *   proto - protocol
 *   dst_flag - dst or src port flag, true = dst, false = src
 *
 */
static int ParsePortList(
    RuleTreeNode* rtn, PortVarTable* pvt, PortTable* noname,
    const char* port_str, int dst_flag)
{
    PortObject* portobject = NULL;  /* src or dst */

    /* Get the protocol specific port object */
    if ( rule_proto & (PROTO_BIT__TCP | PROTO_BIT__UDP) )
    {
        portobject = ParsePortListTcpUdpPort(pvt, noname, port_str);
    }
    else /* ICMP, IP  - no real ports just Type and Protocol */
    {
        portobject = PortVarTableFind(pvt, "any");
        if (portobject == NULL)
        {
            ParseError("PortVarTable missing an 'any' variable.");
            return -1;
        }
    }

    DebugFormat(DEBUG_PORTLISTS,"Rule-PortVar Parsed: %s \n",port_str);

    /* !ports - port lists can be mixed 80:90,!82,
    * so the old NOT flag is depracated for port lists
    */

    /* set up any any flags */
    if ( PortObjectHasAny(portobject) )
    {
        if ( dst_flag )
            rtn->flags |= ANY_DST_PORT;
        else
            rtn->flags |= ANY_SRC_PORT;
    }

    /* check for a pure not rule - fatal if we find one */
    if ( PortObjectIsPureNot(portobject) )
    {
        ParseError("Pure NOT ports are not allowed.");
        return -1;
        /*
           if( dst_flag )
           rtn->flags |= EXCEPT_DST_PORT;
           else
           rtn->flags |= EXCEPT_SRC_PORT;
           */
    }

    /*
    * set to the port object for this rules src/dst port,
    * these are used during rtn/otn port verification of the rule.
    */

    if (dst_flag)
        rtn->dst_portobject = portobject;
    else
        rtn->src_portobject = portobject;

    return 0;
}

/****************************************************************************
 *
 * Function: TestHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Check to see if the two header blocks are identical
 *
 * Arguments: rule => uh
 *            rtn  => uuuuhhhhh....
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
static int TestHeader(RuleTreeNode* rule, RuleTreeNode* rtn)
{
    if ((rule == NULL) || (rtn == NULL))
        return 0;

    if (rule->type != rtn->type)
        return 0;

    if (rule->proto != rtn->proto)
        return 0;

    /* For custom rule type declarations */
    if (rule->listhead != rtn->listhead)
        return 0;

    if (rule->flags != rtn->flags)
        return 0;

    if ((rule->sip != NULL) && (rtn->sip != NULL) &&
        (sfvar_compare(rule->sip, rtn->sip) != SFIP_EQUAL))
    {
        return 0;
    }

    if ((rule->dip != NULL) && (rtn->dip != NULL) &&
        (sfvar_compare(rule->dip, rtn->dip) != SFIP_EQUAL))
    {
        return 0;
    }

    /* compare the port group pointers - this prevents confusing src/dst port objects
     * with the same port set, and it's quicker. It does assume that we only have
     * one port object and pointer for each unique port set...this is handled by the
     * parsing and initial port object storage and lookup.  This must be consistent during
     * the rule parsing phase. - man */
    if ((rule->src_portobject != rtn->src_portobject)
        || (rule->dst_portobject != rtn->dst_portobject))
    {
        return 0;
    }

    return 1;
}

/**returns matched header node.
*/
static RuleTreeNode* findHeadNode(
    SnortConfig* sc, RuleTreeNode* testNode,
    PolicyId policyId)
{
    RuleTreeNode* rtn;
    OptTreeNode* otn;
    SFGHASH_NODE* hashNode;

    for (hashNode = sfghash_findfirst(sc->otn_map);
        hashNode;
        hashNode = sfghash_findnext(sc->otn_map))
    {
        otn = (OptTreeNode*)hashNode->data;
        rtn = getRtnFromOtn(otn, policyId);

        if (TestHeader(rtn, testNode))
            return rtn;
    }

    return NULL;
}

/****************************************************************************
 *
 * Function: XferHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Transfer the rule block header data from point A to point B
 *
 * Arguments: rule => the place to xfer from
 *            rtn => the place to xfer to
 *
 * Returns: void function
 *
 ***************************************************************************/
static void XferHeader(RuleTreeNode* test_node, RuleTreeNode* rtn)
{
    rtn->flags = test_node->flags;
    rtn->type = test_node->type;
    rtn->sip = test_node->sip;
    rtn->dip = test_node->dip;

    rtn->proto = test_node->proto;

    rtn->src_portobject = test_node->src_portobject;
    rtn->dst_portobject = test_node->dst_portobject;
}

/****************************************************************************
 *
 * Function: AddRuleFuncToList(int (*func)(), RuleTreeNode *)
 *
 * Purpose:  Adds RuleTreeNode associated detection functions to the
 *          current rule's function list
 *
 * Arguments: *func => function pointer to the detection function
 *            rtn   => pointer to the current rule
 *
 * Returns: void function
 *
 ***************************************************************************/
static void AddRuleFuncToList(
    int (* rfunc) (Packet*, RuleTreeNode*, struct RuleFpList*, int),
    RuleTreeNode* rtn)
{
    RuleFpList* idx;

    DebugMessage(DEBUG_CONFIGRULES,"Adding new rule to list\n");

    idx = rtn->rule_func;
    if (idx == NULL)
    {
        rtn->rule_func = (RuleFpList*)snort_calloc(sizeof(RuleFpList));
        rtn->rule_func->RuleHeadFunc = rfunc;
    }
    else
    {
        while (idx->next != NULL)
            idx = idx->next;

        idx->next = (RuleFpList*)snort_calloc(sizeof(RuleFpList));
        idx = idx->next;
        idx->RuleHeadFunc = rfunc;
    }
}

/****************************************************************************
 *
 * Function: AddrToFunc(RuleTreeNode *, u_long, u_long, int, int)
 *
 * Purpose: Links the proper IP address testing function to the current RTN
 *          based on the address, netmask, and addr flags
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            mode => indicates whether this is a rule for the source
 *                    or destination IP for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
static void AddrToFunc(RuleTreeNode* rtn, int mode)
{
    /*
     * if IP and mask are both 0, this is a "any" IP and we don't need to
     * check it
     */
    switch (mode)
    {
    case SRC:
        if ((rtn->flags & ANY_SRC_IP) == 0)
        {
            DebugMessage(DEBUG_CONFIGRULES,"CheckSrcIP -> ");
            AddRuleFuncToList(CheckSrcIP, rtn);
        }

        break;

    case DST:
        if ((rtn->flags & ANY_DST_IP) == 0)
        {
            DebugMessage(DEBUG_CONFIGRULES,"CheckDstIP -> ");
            AddRuleFuncToList(CheckDstIP, rtn);
        }

        break;
    }
}

/****************************************************************************
 *
 * Function: PortToFunc(RuleTreeNode *, int, int, int)
 *
 * Purpose: Links in the port analysis function for the current rule
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            any_flag =>  accept any port if set
 *            except_flag => indicates negation (logical NOT) of the test
 *            mode => indicates whether this is a rule for the source
 *                    or destination port for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
static void PortToFunc(RuleTreeNode* rtn, int any_flag, int except_flag, int mode)
{
    /*
     * if the any flag is set we don't need to perform any test to match on
     * this port
     */
    if (any_flag)
        return;

    /* if the except_flag is up, test with the "NotEq" funcs */
    if (except_flag)
    {
        switch (mode)
        {
        case SRC:
            DebugMessage(DEBUG_CONFIGRULES,"CheckSrcPortNotEq -> ");
            AddRuleFuncToList(CheckSrcPortNotEq, rtn);
            break;

        case DST:
            DebugMessage(DEBUG_CONFIGRULES,"CheckDstPortNotEq -> ");
            AddRuleFuncToList(CheckDstPortNotEq, rtn);
            break;
        }

        return;
    }
    /* default to setting the straight test function */
    switch (mode)
    {
    case SRC:
        DebugMessage(DEBUG_CONFIGRULES,"CheckSrcPortEqual -> ");
        AddRuleFuncToList(CheckSrcPortEqual, rtn);
        break;

    case DST:
        DebugMessage(DEBUG_CONFIGRULES,"CheckDstPortEqual -> ");
        AddRuleFuncToList(CheckDstPortEqual, rtn);
        break;
    }
}

/****************************************************************************
 *
 * Function: SetupRTNFuncList(RuleTreeNode *)
 *
 * Purpose: Configures the function list for the rule header detection
 *          functions (addrs and ports)
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *
 * Returns: void function
 *
 ***************************************************************************/
static void SetupRTNFuncList(RuleTreeNode* rtn)
{
    DebugMessage(DEBUG_CONFIGRULES,"Initializing RTN function list!\n");
    DebugMessage(DEBUG_CONFIGRULES,"Functions: ");

    if (rtn->flags & BIDIRECTIONAL)
    {
        DebugMessage(DEBUG_CONFIGRULES,"CheckBidirectional->\n");
        AddRuleFuncToList(CheckBidirectional, rtn);
    }
    else
    {
        /* Attach the proper port checking function to the function list */
        /*
         * the in-line "if's" check to see if the "any" or "not" flags have
         * been set so the PortToFunc call can determine which port testing
         * function to attach to the list
         */
        PortToFunc(rtn, (rtn->flags & ANY_DST_PORT ? 1 : 0),
            (rtn->flags & EXCEPT_DST_PORT ? 1 : 0), DST);

        /* as above */
        PortToFunc(rtn, (rtn->flags & ANY_SRC_PORT ? 1 : 0),
            (rtn->flags & EXCEPT_SRC_PORT ? 1 : 0), SRC);

        /* link in the proper IP address detection function */
        AddrToFunc(rtn, SRC);

        /* last verse, same as the first (but for dest IP) ;) */
        AddrToFunc(rtn, DST);
    }

    DebugMessage(DEBUG_CONFIGRULES,"RuleListEnd\n");

    /* tack the end (success) function to the list */
    AddRuleFuncToList(RuleListEnd, rtn);
}

/****************************************************************************
 *
 * Function: ProcessHeadNode(RuleTreeNode *, ListHead *, int)
 *
 * Purpose:  Process the header block info and add to the block list if
 *           necessary
 *
 * Arguments: test_node => data generated by the rules parsers
 *            list => List Block Header refernece
 *            protocol => ip protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
static RuleTreeNode* ProcessHeadNode(
    SnortConfig* sc, RuleTreeNode* test_node, ListHead* list)
{
    RuleTreeNode* rtn = findHeadNode(
        sc, test_node, get_ips_policy()->policy_id);

    /* if it doesn't match any of the existing nodes, make a new node and
     * stick it at the end of the list */
    if (rtn == NULL)
    {
        DebugMessage(DEBUG_CONFIGRULES,"Building New Chain head node\n");
        head_count++;

        rtn = (RuleTreeNode*)snort_calloc(sizeof(RuleTreeNode));
        rtn->otnRefCount++;

        /* copy the prototype header info into the new header block */
        XferHeader(test_node, rtn);

        /* initialize the function list for the new RTN */
        SetupRTNFuncList(rtn);

        /* add link to parent listhead */
        rtn->listhead = list;

        DebugFormat(DEBUG_CONFIGRULES,
            "New Chain head flags = 0x%X\n", rtn->flags);
    }
    else
    {
        rtn->otnRefCount++;
        FreeRuleTreeNode(test_node);
    }

    return rtn;
}

/****************************************************************************
 *
 * Function: mergeDuplicateOtn()
 *
 * Purpose:  Conditionally removes duplicate SID/GIDs. Keeps duplicate with
 *           higher revision.  If revision is the same, keeps newest rule.
 *
 * Arguments: otn_cur => The current version
 *            rtn => the RTN chain to check
 *            char => String describing the rule
 *
 * Returns: 0 if original rule stays, 1 if new rule stays
 *
 ***************************************************************************/
static int mergeDuplicateOtn(
    SnortConfig* sc, OptTreeNode* otn_cur,
    OptTreeNode* otn_new, RuleTreeNode* rtn_new)
{
    RuleTreeNode* rtn_cur = NULL;
    RuleTreeNode* rtnTmp2 = NULL;
    unsigned i;

    if (otn_cur->proto != otn_new->proto)
    {
        ParseError("GID %u SID %u in rule duplicates previous rule, with "
            "different protocol.",
            otn_new->sigInfo.generator, otn_new->sigInfo.id);
        return 0;
    }

    rtn_cur = getRtnFromOtn(otn_cur);

    if ((rtn_cur != NULL) && (rtn_cur->type != rtn_new->type))
    {
        ParseError("GID %u SID %u in rule duplicates previous rule, with "
            "different type.",
            otn_new->sigInfo.generator, otn_new->sigInfo.id);
        return 0;
    }

    if ( otn_new->sigInfo.rev < otn_cur->sigInfo.rev )
    {
        //current OTN is newer version. Keep current and discard the new one.
        //OTN is for new policy group, salvage RTN
        deleteRtnFromOtn(otn_new);

        ParseWarning(WARN_RULES,
            "%u:%u duplicates previous rule. Using revision %u.",
            otn_cur->sigInfo.generator, otn_cur->sigInfo.id, otn_cur->sigInfo.rev);

        /* Now free the OTN itself -- this function is also used
         * by the hash-table calls out of OtnRemove, so it cannot
         * be modified to delete data for rule options */
        OtnFree(otn_new);

        //Add rtn to current otn for the first rule instance in a policy,
        //otherwise ignore it
        if (rtn_cur == NULL)
        {
            addRtnToOtn(otn_cur, rtn_new);
        }
        else
        {
            DestroyRuleTreeNode(rtn_new);
        }

        return 0;
    }

    //delete current rule instance and keep the new one

    for (i = 0; i < otn_cur->proto_node_num; i++)
    {
        rtnTmp2 = deleteRtnFromOtn(otn_cur, i);

        if (rtnTmp2 && (i != get_ips_policy()->policy_id))
        {
            addRtnToOtn(otn_new, rtnTmp2, i);
        }
    }

    if (rtn_cur)
    {
        if (SnortConfig::conf_error_out())
        {
            ParseError(
                "%u:%u:%u duplicates previous rule.",
                otn_new->sigInfo.generator, otn_new->sigInfo.id, otn_new->sigInfo.rev);
            return 0;
        }
        else
        {
            ParseWarning(WARN_RULES,
                "%u:%u duplicates previous rule. Using revision %u.",
                otn_new->sigInfo.generator, otn_new->sigInfo.id, otn_new->sigInfo.rev);
        }
    }
    OtnRemove(sc->otn_map, otn_cur);
    DestroyRuleTreeNode(rtn_cur);

    return 1;
}

PatternMatchData* get_pmd(OptFpList* ofl)
{
    if ( !ofl->ips_opt )
        return nullptr;

    return ofl->ips_opt->get_pattern();
}

static void finalize_content(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl);

    if ( !pmd )
        return;

    if ( pmd->negated )
        pmd->last_check = (PmdLastCheck*)snort_calloc(
            ThreadConfig::get_instance_max(), sizeof(*pmd->last_check));
}

bool is_fast_pattern_only(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl);

    if ( !pmd )
        return false;

    return pmd->fp_only > 0;
}

static void clear_fast_pattern_only(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl);

    if ( pmd && pmd->fp_only > 0 )
        pmd->fp_only = 0;
}

static void ValidateFastPattern(OptTreeNode* otn)
{
    OptFpList* fp = nullptr;
    bool relative_is_bad_mkay = false;

    for (OptFpList* fpl = otn->opt_func; fpl; fpl = fpl->next)
    {
        // a relative option is following a fast_pattern/only and
        if ( relative_is_bad_mkay )
        {
            if (fpl->isRelative)
            {
                assert(fp);
                assert(false);  // fp only is set internally; should not be bad
                clear_fast_pattern_only(fp);
            }
        }

        // reset the check if one of these are present.
        if ( fpl->ips_opt and !fpl->ips_opt->get_pattern() )
        {
            if ( fpl->ips_opt->get_cursor_type() > CAT_NONE )
                relative_is_bad_mkay = false;
        }
        // set/unset the check on content options.
        else
        {
            if ( is_fast_pattern_only(fpl) )
            {
                fp = fpl;
                relative_is_bad_mkay = true;
            }
            else
                relative_is_bad_mkay = false;
        }
        finalize_content(fpl);
    }
}

int get_rule_count()
{ return rule_count; }

void parse_rule_init()
{
    rule_count = 0;
    detect_rule_count = 0;
    builtin_rule_count = 0;
    so_rule_count = 0;
    head_count = 0;
    otn_count = 0;
    rule_proto = 0;

    memset(&ipCnt, 0, sizeof(ipCnt));
    memset(&icmpCnt, 0, sizeof(icmpCnt));
    memset(&tcpCnt, 0, sizeof(tcpCnt));
    memset(&udpCnt, 0, sizeof(udpCnt));
    memset(&svcCnt, 0, sizeof(svcCnt));
}

void parse_rule_term()
{ }

void parse_rule_print()
{
    if ( !rule_count )
        return;

    LogLabel("rule counts");
    LogCount("total rules loaded", rule_count);
    LogCount("text rules", detect_rule_count);
    LogCount("builtin rules", builtin_rule_count);
    LogCount("so rules", so_rule_count);
    LogCount("option chains", otn_count);
    LogCount("chain headers", head_count);

    unsigned ip = ipCnt.src + ipCnt.dst + ipCnt.any + ipCnt.both + ipCnt.nfp;
    unsigned icmp = icmpCnt.src + icmpCnt.dst + icmpCnt.any + icmpCnt.both + icmpCnt.nfp;
    unsigned tcp = tcpCnt.src + tcpCnt.dst + tcpCnt.any + tcpCnt.both + tcpCnt.nfp;
    unsigned udp = udpCnt.src + udpCnt.dst + udpCnt.any + udpCnt.both + udpCnt.nfp;

    if ( !ip and !icmp and !tcp and !udp )
        return;

    LogLabel("port rule counts");
    LogMessage("%8s%8s%8s%8s%8s\n", " ", "tcp", "udp", "icmp", "ip");

    if ( tcpCnt.any || udpCnt.any || icmpCnt.any || ipCnt.any )
        LogMessage("%8s%8u%8u%8u%8u\n", "any",
            tcpCnt.any, udpCnt.any, icmpCnt.any, ipCnt.any);

    if ( tcpCnt.src || udpCnt.src || icmpCnt.src || ipCnt.src )
        LogMessage("%8s%8u%8u%8u%8u\n", "src",
            tcpCnt.src, udpCnt.src, icmpCnt.src, ipCnt.src);

    if ( tcpCnt.dst || udpCnt.dst || icmpCnt.dst || ipCnt.dst )
        LogMessage("%8s%8u%8u%8u%8u\n", "dst",
            tcpCnt.dst, udpCnt.dst, icmpCnt.dst, ipCnt.dst);

    if ( tcpCnt.both || udpCnt.both || icmpCnt.both || ipCnt.both )
        LogMessage("%8s%8u%8u%8u%8u\n", "both",
            tcpCnt.both, udpCnt.both, icmpCnt.both, ipCnt.both);

    if ( tcpCnt.nfp || udpCnt.nfp || icmpCnt.nfp || ipCnt.nfp )
        LogMessage("%8s%8u%8u%8u%8u\n", "slow",
            tcpCnt.nfp, udpCnt.nfp, icmpCnt.nfp, ipCnt.nfp);

    LogMessage("%8s%8u%8u%8u%8u\n", "total", tcp, udp, icmp, ip);
}

void parse_rule_type(SnortConfig* sc, const char* s, RuleTreeNode& rtn)
{
    memset(&rtn, 0, sizeof(rtn));
    rtn.type = get_rule_type(s);

    if ( rtn.type == RULE_TYPE__NONE )
    {
        s_ignore = true;
        return;
    }
    else
    {
        rtn.listhead = get_rule_list(sc, s);
    }

    if ( !rtn.listhead )
        ParseError("unconfigured rule action '%s'", s);
}

void parse_rule_proto(SnortConfig*, const char* s, RuleTreeNode& rtn)
{
    if ( s_ignore )
        return;

    if ( !strcmp(s, "tcp") )
        rule_proto = PROTO_BIT__TCP;

    else if ( !strcmp(s, "udp") )
        rule_proto = PROTO_BIT__UDP;

    else if ( !strcmp(s, "icmp") )
        rule_proto = PROTO_BIT__ICMP;

    else if ( !strcmp(s, "ip") )
        rule_proto = PROTO_BIT__IP;

    else
        // this will allow other protocols like http to have ports
        rule_proto = PROTO_BIT__TCP;

    rtn.proto = AddProtocolReference(s);

    if ( rtn.proto <= 0 )
    {
        ParseError("bad protocol: %s", s);
        rule_proto = 0;
    }
}

void parse_rule_nets(
    SnortConfig* sc, const char* s, bool src, RuleTreeNode& rtn)
{
    if ( s_ignore )
        return;

    ProcessIP(sc, s, &rtn, src ? SRC : DST, 0);
}

void parse_rule_ports(
    SnortConfig*, const char* s, bool src, RuleTreeNode& rtn)
{
    if ( s_ignore )
        return;

    IpsPolicy* p = get_ips_policy();

    if ( ParsePortList(&rtn, p->portVarTable, p->nonamePortVarTable,
        s, src ? SRC : DST) )
    {
        ParseError("bad ports: '%s'", s);
    }
}

void parse_rule_dir(SnortConfig*, const char* s, RuleTreeNode& rtn)
{
    if ( s_ignore )
        return;

    if (strcmp(s, RULE_DIR_OPT__BIDIRECTIONAL) == 0)
        rtn.flags |= BIDIRECTIONAL;

    else if ( strcmp(s, RULE_DIR_OPT__DIRECTIONAL) )
        ParseError("illegal direction specifier: %s", s);
}

void parse_rule_opt_begin(SnortConfig* sc, const char* key)
{
    if ( s_ignore )
        return;

    IpsManager::option_begin(sc, key, rule_proto);
}

void parse_rule_opt_set(
    SnortConfig* sc, const char* key, const char* opt, const char* val)
{
    if ( s_ignore )
        return;

    IpsManager::option_set(sc, key, opt, val);
}

void parse_rule_opt_end(SnortConfig* sc, const char* key, OptTreeNode* otn)
{
    if ( s_ignore )
        return;

    RuleOptType type = OPT_TYPE_MAX;
    IpsManager::option_end(sc, otn, otn->proto, key, type);

    if ( type != OPT_TYPE_META )
        otn->num_detection_opts++;
}

OptTreeNode* parse_rule_open(SnortConfig* sc, RuleTreeNode& rtn, bool stub)
{
    if ( s_ignore )
        return nullptr;

    if ( stub )
    {
        parse_rule_proto(sc, "tcp", rtn);
        parse_rule_nets(sc, "any", true, rtn);
        parse_rule_ports(sc, "any", true, rtn);
        parse_rule_dir(sc, "->", rtn);
        parse_rule_nets(sc, "any", false, rtn);
        parse_rule_ports(sc, "any", false, rtn);
    }
    OptTreeNode* otn = (OptTreeNode*)snort_calloc(sizeof(OptTreeNode));
    otn->state = (OtnState*)snort_calloc(ThreadConfig::get_instance_max(), sizeof(OtnState));

    if ( !stub )
        otn->sigInfo.generator = GENERATOR_SNORT_ENGINE;

    otn->chain_node_number = otn_count;
    otn->proto = rtn.proto;
    otn->enabled = SnortConfig::get_default_rule_state();

    IpsManager::reset_options();

    return otn;
}

// return nullptr if nothing left to do
// for so rules, return the detection options and continue parsing
// but if already entered, don't recurse again
const char* parse_rule_close(SnortConfig* sc, RuleTreeNode& rtn, OptTreeNode* otn)
{
    if ( s_ignore )
    {
        s_ignore = false;
        return nullptr;
    }

    static bool entered = false;
    const char* so_opts = nullptr;

    if ( entered )
        entered = false;

    else if ( otn->soid )
    {
        so_opts = SoManager::get_so_options(otn->soid);

        if ( !so_opts )
            ParseError("SO rule %s not loaded.", otn->soid);
        else
        {
            // FIXIT-L gid may be overwritten when set to 3 upon close
            otn->sigInfo.generator = GENERATOR_SNORT_SHARED;
            entered = true;
            return so_opts;
        }
    }

    bool has_fp = set_fp_content(otn);

    /* The IPs in the test node get free'd in ProcessHeadNode if there is
     * already a matching RTN.  The portobjects will get free'd when the
     * port var table is free'd */
    RuleTreeNode* new_rtn = ProcessHeadNode(sc, &rtn, rtn.listhead);

    addRtnToOtn(otn, new_rtn);

    OptTreeNode* otn_dup =
        OtnLookup(sc->otn_map, otn->sigInfo.generator, otn->sigInfo.id);

    if ( otn_dup )
    {
        otn->ruleIndex = otn_dup->ruleIndex;

        if (mergeDuplicateOtn(sc, otn_dup, otn, new_rtn) == 0)
        {
            /* We are keeping the old/dup OTN and trashing the new one
             * we just created - it's free'd in the remove dup function */
            return nullptr;
        }
    }
    otn_count++;
    rule_count++;

    // FIXIT-L need more reliable way of knowing type of rule instead of
    // hard coding these gids do GIDs actually matter anymore (w/o conflict
    // with builtins)?

    if ( otn->sigInfo.generator == GENERATOR_SNORT_ENGINE )
    {
        otn->sigInfo.text_rule = true;
        detect_rule_count++;
    }
    else if ( otn->sigInfo.generator == GENERATOR_SNORT_SHARED )
    {
        otn->sigInfo.text_rule = true;
        so_rule_count++;
    }
    else
    {
        if ( !otn->sigInfo.generator )
            ParseError("gid must set in builtin rules");

        if ( otn->num_detection_opts )
            ParseError("%u:%u builtin rules do not support detection options",
                otn->sigInfo.generator, otn->sigInfo.id);

        otn->sigInfo.text_rule = false;
        builtin_rule_count++;
    }

    if ( !otn_dup )
        otn->ruleIndex = parser_get_rule_index(otn->sigInfo.generator, otn->sigInfo.id);

    OptFpList* fpl = AddOptFuncToList(OptListEnd, otn);
    fpl->type = RULE_OPTION_TYPE_LEAF_NODE;

    ValidateFastPattern(otn);
    OtnLookupAdd(sc->otn_map, otn);

    if ( is_service_protocol(otn->proto) )
        add_service_to_otn(sc, otn, get_protocol_name(otn->proto));

    /*
     * The src/dst port parsing must be done before the Head Nodes are processed, since they must
     * compare the ports/port_objects to find the right rtn list to add the otn rule to.
     *
     * After otn processing we can finalize port object processing for this rule
     */
    if ( FinishPortListRule(
            sc->port_tables, new_rtn, otn, rtn.proto, has_fp, sc->fast_pattern_config) )
        ParseError("Failed to finish a port list rule.");

    return nullptr;
}

