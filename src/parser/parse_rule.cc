//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parse_rule.h"

#include "actions/actions.h"
#include "detection/detect.h"
#include "detection/fp_config.h"
#include "detection/fp_utils.h"
#include "detection/rtn_checks.h"
#include "detection/treenodes.h"
#include "framework/decode_data.h"
#include "hash/xhash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "managers/so_manager.h"
#include "ports/rule_port_tables.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sf_vartable.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"
#include "ips_options/extract.h"

#include "parser.h"
#include "parse_conf.h"
#include "parse_ports.h"

#include "parser.h"
#include "cmd_line.h"
#include "config_file.h"
#include "parse_conf.h"
#include "parse_ports.h"

using namespace snort;

#define SRC  0
#define DST  1

/* rule counts for port lists */
struct rule_count_t
{
    int src;
    int dst;
    int any;
    int both;
};

static int rule_count = 0;
static int prev_rule_count = 0;
static int skip_count = 0;
static int detect_rule_count = 0;
static int builtin_rule_count = 0;
static int so_rule_count = 0;
static int head_count = 0;          // rule headers
static int otn_count = 0;           // rule bodies
static int dup_count = 0;           // rule bodies
static int prev_dup_count = 0;
static int rule_proto = 0;

static rule_count_t tcpCnt;
static rule_count_t udpCnt;
static rule_count_t icmpCnt;
static rule_count_t ipCnt;
static rule_count_t svcCnt;  // dummy for now

static bool s_ignore = false;  // for skipping drop rules when not inline, etc.
static bool s_capture = false;
static bool buf_is_set = false;

static std::string s_type;
static std::string s_body;

static bool action_file_id = false;
static bool strict_rtn_reduction = false;

struct SoRule
{
    SoRule(RuleTreeNode* rtn, const OptTreeNode* otn) :
        rtn(rtn), gid(otn->sigInfo.gid), sid(otn->sigInfo.sid), rev(otn->sigInfo.rev) { }

    RuleTreeNode* rtn;
    uint32_t gid;
    uint32_t sid;
    uint32_t rev;
};

static SoRule* s_so_rule = nullptr;

static bool rule_is_stateless()
{ return action_file_id; }

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

static int ProcessIP(SnortConfig* sc, const char* addr, RuleTreeNode* rtn, int mode, int)
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

        if ( !rtn->sip )
        {
            sfip_var_t* tmp = sfvt_lookup_var(ip_vartable, addr);
            if ( tmp )
            {
                rtn->sip = sfvar_create_alias(tmp, tmp->name);
                ret = rtn->sip ?  SFIP_SUCCESS : SFIP_FAILURE;
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
        if ( ret == SFIP_LOOKUP_FAILURE and sc->dump_rule_info() )
            ret = sfvt_add_to_var(ip_vartable, rtn->sip, "any");

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
            rtn->flags |= RuleTreeNode::ANY_SRC_IP;
        }
    }
    /* mode == DST */
    else
    {
        int ret;

        if ( !rtn->dip )
        {
            sfip_var_t* tmp = sfvt_lookup_var(ip_vartable, addr);
            if ( tmp )
            {
                rtn->dip = sfvar_create_alias(tmp, tmp->name);
                ret = rtn->dip ?  SFIP_SUCCESS : SFIP_FAILURE;
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

        if ( ret == SFIP_LOOKUP_FAILURE and sc->dump_rule_info() )
            ret = sfvt_add_to_var(ip_vartable, rtn->dip, "any");

        if ( ret != SFIP_SUCCESS )
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
            rtn->flags |= RuleTreeNode::ANY_DST_IP;
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
*/
static PortObject* ParsePortListTcpUdpPort(
    PortVarTable* pvt, PortTable* noname, const char* port_str)
{
    PortObject* portobject;
    POParser poparser;

    if ( !pvt or !noname or !port_str )
        return nullptr;

    /* 1st - check if we have an any port */
    if ( strcasecmp(port_str,"any")== 0 )
    {
        portobject = PortVarTableFind(pvt, "any");
        if ( !portobject )
            ParseAbort("PortVarTable missing an 'any' variable.");

        return portobject;
    }
    /* 2nd - check if we have a PortVar */
    else if ( port_str[0]=='$' )
    {
        /*||isalpha(port_str[0])*/ /*TODO: interferes with protocol names for ports*/
        const char* name = port_str + 1;

        /* look it up  in the port var table */
        portobject = PortVarTableFind(pvt, name, true);
        if ( !portobject )
            ParseAbort("***PortVar Lookup failed on '%s'.", port_str);

    }
    /* 3rd -  and finally process a raw port list */
    else
    {
        /* port list = [p,p,p:p,p,...] or p or p:p , no embedded spaces due to tokenizer */
        PortObject* pox;

        portobject = PortObjectParseString(pvt, &poparser, nullptr, port_str, 0);

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
            PortObjectFree(portobject);
            portobject = pox;
        }
        else
        {
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
 *   dst_flag - dst or src port flag, true = dst, false = src
 *
 */
static int ParsePortList(
    RuleTreeNode* rtn, PortVarTable* pvt, PortTable* noname,
    const char* port_str, int dst_flag)
{
    PortObject* portobject;  /* src or dst */

    /* Get the protocol specific port object */
    if ( rule_proto & (PROTO_BIT__TCP | PROTO_BIT__UDP | PROTO_BIT__PDU) )
    {
        portobject = ParsePortListTcpUdpPort(pvt, noname, port_str);
    }
    else /* ICMP, IP  - no real ports just Type and Protocol */
    {
        portobject = PortVarTableFind(pvt, "any");
        if ( !portobject )
        {
            ParseError("PortVarTable missing an 'any' variable.");
            return -1;
        }
    }

    /* !ports - port lists can be mixed 80:90,!82,
    * so the old NOT flag is deprecated for port lists
    */

    /* set up any any flags */
    if ( PortObjectHasAny(portobject) )
    {
        if ( dst_flag )
            rtn->flags |= RuleTreeNode::ANY_DST_PORT;
        else
            rtn->flags |= RuleTreeNode::ANY_SRC_PORT;
    }

    /* check for a pure not rule - fatal if we find one */
    if ( PortObjectIsPureNot(portobject) )
    {
        ParseError("Pure NOT ports are not allowed.");
        return -1;
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

void set_strict_rtn_reduction(bool new_strict_rtn_reduction)
{ strict_rtn_reduction = new_strict_rtn_reduction; }

bool same_headers(RuleTreeNode* rule, RuleTreeNode* rtn)
{
    if ( !rule or !rtn )
        return false;

    if (rule->action != rtn->action)
        return false;

    if (rule->snort_protocol_id != rtn->snort_protocol_id)
        return false;

    /* For custom rule type declarations */
    if (rule->listhead != rtn->listhead)
        return false;

    if (rule->flags != rtn->flags)
        return false;

    if ( rule->sip and rtn->sip and sfvar_compare(rule->sip, rtn->sip) != SFIP_EQUAL )
        return false;

    if ( rule->dip and rtn->dip and sfvar_compare(rule->dip, rtn->dip) != SFIP_EQUAL )
        return false;

    if ( strict_rtn_reduction )
    {
        if ( rule->src_portobject and rtn->src_portobject
            and !PortObjectEqual(rule->src_portobject, rtn->src_portobject) )
            return false;

        if ( rule->dst_portobject and rtn->dst_portobject
            and !PortObjectEqual(rule->dst_portobject, rtn->dst_portobject) )
            return false;
    }
    else
    {
        if ( (rule->src_portobject != rtn->src_portobject)
            or (rule->dst_portobject != rtn->dst_portobject) )
            return false;
    }

    return true;
}

static void XferHeader(RuleTreeNode* from, RuleTreeNode* to)
{
    to->flags = from->flags;
    to->action = from->action;
    to->sip = from->sip;
    to->dip = from->dip;

    to->listhead = from->listhead;
    to->snort_protocol_id = from->snort_protocol_id;

    to->src_portobject = from->src_portobject;
    to->dst_portobject = from->dst_portobject;

    to->header = from->header;
}

/****************************************************************************
 * Purpose:  Adds RuleTreeNode associated detection functions to the
 *          current rule's function list
 *
 * Arguments: *func => function pointer to the detection function
 *            rtn   => pointer to the current rule
 ***************************************************************************/
static void AddRuleFuncToList(
    int (* rfunc)(Packet*, RuleTreeNode*, struct RuleFpList*, int),
    RuleTreeNode* rtn)
{
    RuleFpList* idx = rtn->rule_func;

    if ( !idx )
    {
        rtn->rule_func = new RuleFpList;
        rtn->rule_func->RuleHeadFunc = rfunc;
    }
    else
    {
        while ( idx->next )
            idx = idx->next;

        idx->next = new RuleFpList;
        idx = idx->next;
        idx->RuleHeadFunc = rfunc;
    }
}

/****************************************************************************
 * Purpose: Links the proper IP address testing function to the current RTN
 *          based on the address, netmask, and addr flags
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            mode => indicates whether this is a rule for the source
 *                    or destination IP for the rule
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
        if ((rtn->flags & RuleTreeNode::ANY_SRC_IP) == 0)
        {
            AddRuleFuncToList(CheckSrcIP, rtn);
        }
        break;

    case DST:
        if ((rtn->flags & RuleTreeNode::ANY_DST_IP) == 0)
        {
            AddRuleFuncToList(CheckDstIP, rtn);
        }
        break;
    }
}

/****************************************************************************
 * Purpose: Links in the port analysis function for the current rule
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            any_flag =>  accept any port if set
 *            except_flag => indicates negation (logical NOT) of the test
 *            mode => indicates whether this is a rule for the source
 *                    or destination port for the rule
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
            AddRuleFuncToList(CheckSrcPortNotEq, rtn);
            break;

        case DST:
            AddRuleFuncToList(CheckDstPortNotEq, rtn);
            break;
        }

        return;
    }
    /* default to setting the straight test function */
    switch (mode)
    {
    case SRC:
        AddRuleFuncToList(CheckSrcPortEqual, rtn);
        break;

    case DST:
        AddRuleFuncToList(CheckDstPortEqual, rtn);
        break;
    }
}

// Configures the function list for the rule header detection
// functions (addrs and ports)
static void SetupRTNFuncList(RuleTreeNode* rtn)
{
    if (rtn->flags & RuleTreeNode::BIDIRECTIONAL)
        AddRuleFuncToList(CheckBidirectional, rtn);

    else
    {
        PortToFunc(rtn, (rtn->any_dst_port() ? 1 : 0), 0, DST);
        PortToFunc(rtn, (rtn->any_src_port() ? 1 : 0), 0, SRC);

        AddrToFunc(rtn, SRC);
        AddrToFunc(rtn, DST);
    }

    if ( rtn->snort_protocol_id < SNORT_PROTO_FILE )
        AddRuleFuncToList(CheckProto, rtn);
    else
        rtn->flags |= RuleTreeNode::USER_MODE;

    AddRuleFuncToList(RuleListEnd, rtn);
}

// make a new node and stick it at the end of the list
static RuleTreeNode* transfer_rtn(RuleTreeNode* tmpl)
{
    head_count++;
    auto rtn = new RuleTreeNode;
    XferHeader(tmpl, rtn);
    SetupRTNFuncList(rtn);
    return rtn;
}

// Conditionally removes duplicate OTN. Keeps duplicate with
// higher revision.  If revision is the same, keeps newest rule.
static int mergeDuplicateOtn(
    SnortConfig* sc, OptTreeNode* otn_cur,
    OptTreeNode* otn_new, RuleTreeNode* rtn_new)
{
    if (otn_cur->snort_protocol_id != otn_new->snort_protocol_id)
    {
        ParseError("GID %u SID %u in rule duplicates previous rule, with different protocol.",
            otn_new->sigInfo.gid, otn_new->sigInfo.sid);
        return true;
    }

    RuleTreeNode* rtn_cur = getRtnFromOtn(otn_cur);

    if ( rtn_cur and rtn_cur->action != rtn_new->action )
    {
        ParseError("GID %u SID %u in rule duplicates previous rule, with different type.",
            otn_new->sigInfo.gid, otn_new->sigInfo.sid);
        return true;
    }

    if ( otn_new->sigInfo.rev < otn_cur->sigInfo.rev )
    {
        // keep orig, free new
        ParseWarning(WARN_RULES, "%u:%u duplicates previous rule. Using revision %u.",
            otn_cur->sigInfo.gid, otn_cur->sigInfo.sid, otn_cur->sigInfo.rev);

        // OTN is for new policy group, salvage RTN
        deleteRtnFromOtn(otn_new, sc);

        // Now free the OTN itself -- this function is also used
        // by the hash-table calls out of OtnRemove, so it cannot
        // be modified to delete data for rule options
        delete otn_new;

        // Add rtn to current otn for the first rule instance in a policy,
        // otherwise ignore it
        if ( !rtn_cur )
            addRtnToOtn(sc, otn_cur, rtn_new);
        else
            DestroyRuleTreeNode(rtn_new);

        return true;
    }
    // keep new, free orig
    ParseWarning(WARN_RULES, "%u:%u duplicates previous rule. Using revision %u.",
        otn_new->sigInfo.gid, otn_new->sigInfo.sid, otn_new->sigInfo.rev);

    for ( unsigned i = 0; i < otn_cur->proto_node_num; ++i )
    {
        RuleTreeNode* rtnTmp2 = deleteRtnFromOtn(otn_cur, i, sc, (rtn_cur != rtn_new));

        if ( rtnTmp2 and (i != get_ips_policy()->policy_id) )
            addRtnToOtn(sc, otn_new, rtnTmp2, i);
    }

    if (rtn_cur)
        DestroyRuleTreeNode(rtn_cur);

    OtnRemove(sc->otn_map, otn_cur);
    return false;
}

namespace snort
{
int get_rule_count()
{ return rule_count; }
}

int get_policy_loaded_rule_count()
{
    auto policy_rule_count = rule_count - prev_rule_count;
    prev_rule_count = rule_count;
    return policy_rule_count;
}

int get_policy_shared_rule_count()
{
    auto policy_rule_count = dup_count - prev_dup_count;
    prev_dup_count = dup_count;
    return policy_rule_count;
}

void parse_rule_init()
{
    rule_count = 0;
    prev_rule_count = 0;
    skip_count = 0;
    detect_rule_count = 0;
    builtin_rule_count = 0;
    so_rule_count = 0;
    head_count = 0;
    otn_count = 0;
    dup_count = 0;
    prev_dup_count = 0;
    rule_proto = 0;

    memset(&ipCnt, 0, sizeof(ipCnt));
    memset(&icmpCnt, 0, sizeof(icmpCnt));
    memset(&tcpCnt, 0, sizeof(tcpCnt));
    memset(&udpCnt, 0, sizeof(udpCnt));
    memset(&svcCnt, 0, sizeof(svcCnt));
}

void parse_rule_term()
{ }

void parse_rule_print(unsigned fb_total, unsigned fb_unchk, unsigned fb_unset)
{
    if ( !rule_count and !skip_count )
        return;

    LogLabel("rule counts");
    LogCount("total rules loaded", rule_count);
    LogCount("total rules not loaded", skip_count);
    LogCount("duplicate rules", dup_count);
    LogCount("text rules", detect_rule_count);
    LogCount("builtin rules", builtin_rule_count);
    LogCount("so rules", so_rule_count);
    LogCount("option chains", otn_count);
    LogCount("chain headers", head_count);
    LogCount("flowbits", fb_total);
    LogCount("flowbits not checked", fb_unchk);
    LogCount("flowbits not set", fb_unset);

    unsigned ip = ipCnt.src + ipCnt.dst + ipCnt.any + ipCnt.both;
    unsigned icmp = icmpCnt.src + icmpCnt.dst + icmpCnt.any + icmpCnt.both;
    unsigned tcp = tcpCnt.src + tcpCnt.dst + tcpCnt.any + tcpCnt.both;
    unsigned udp = udpCnt.src + udpCnt.dst + udpCnt.any + udpCnt.both;

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

    LogMessage("%8s%8u%8u%8u%8u\n", "total", tcp, udp, icmp, ip);
}

void parse_rule_type(SnortConfig* sc, const char* s, RuleTreeNode& rtn)
{
    IpsPolicy* p = get_ips_policy();

    if ( !p->action_override.empty() )
        s = p->action_override.c_str();

    auto it = p->action_map.find(s);

    if ( it != p->action_map.end() )
        s = it->second.c_str();

    s_type = s;
    rtn = RuleTreeNode();

    if ( s_so_rule )
        return;

    assert(s);

    rtn.action = Actions::get_type(s);

    if ( !Actions::is_valid_action(rtn.action) )
    {
        s_ignore = true;
        ParseError("unknown rule action '%s'", s);
        return;
    }
    if (!strcmp(s,"file_id"))
        action_file_id = true;
    else
        action_file_id = false;

    if ( sc->dump_rule_meta() )
        rtn.header = new RuleHeader(s);

    rtn.listhead = get_rule_list(sc, s);

    if ( !rtn.listhead )
    {
        CreateRuleType(sc, s, rtn.action);
        rtn.listhead = get_rule_list(sc, s);
    }

    if ( sc->get_default_rule_state() or rule_is_stateless() )
        rtn.set_enabled();
}

void parse_rule_proto(SnortConfig* sc, const char* s, RuleTreeNode& rtn, bool elided)
{
    if ( s_ignore )
        return;

    if ( !s_so_rule and !elided and rtn.header )
        rtn.header->proto = s;

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
        rule_proto = PROTO_BIT__PDU;

    rtn.snort_protocol_id = sc->proto_ref->add(s);

    if ( rtn.snort_protocol_id == UNKNOWN_PROTOCOL_ID )
    {
        ParseError("bad protocol: %s", s);
        rule_proto = 0;
    }
    else if ( s_so_rule and s_so_rule->rtn->snort_protocol_id != rtn.snort_protocol_id )
        ParseWarning(WARN_RULES, "so rule proto can not be changed");
}

void parse_rule_nets(
    SnortConfig* sc, const char* s, bool src, RuleTreeNode& rtn, bool elided)
{
    if ( s_so_rule )
        return;

    if ( s_ignore )
        return;

    if ( !elided and rtn.header )
    {
        if ( src )
            rtn.header->src_nets = s;
        else
            rtn.header->dst_nets = s;
    }
    ProcessIP(sc, s, &rtn, src ? SRC : DST, 0);
}

void parse_rule_ports(
    SnortConfig*, const char* s, bool src, RuleTreeNode& rtn, bool elided)
{
    if ( s_so_rule )
        return;

    if ( s_ignore )
        return;

    if ( !elided and rtn.header )
    {
        if ( src )
            rtn.header->src_ports = s;
        else
            rtn.header->dst_ports = s;
    }

    IpsPolicy* p = get_ips_policy();

    if ( ParsePortList(&rtn, p->portVarTable, p->nonamePortVarTable, s, src ? SRC : DST) )
        ParseError("bad ports: '%s'", s);
}

void parse_rule_dir(SnortConfig*, const char* s, RuleTreeNode& rtn, bool elided)
{
    if ( s_so_rule )
        return;

    if ( s_ignore )
        return;

    if ( !elided and rtn.header )
        rtn.header->dir = s;

    if (strcmp(s, "<>") == 0)
        rtn.flags |= RuleTreeNode::BIDIRECTIONAL;

    else if ( strcmp(s, "->") )
        ParseError("illegal direction specifier: %s", s);
}

// Values of the rule options "pcre", "regex" and "sd_pattern" are already escaped
// They are not unescaped during the rule parsing
static bool is_already_escaped(const std::string& opt_key)
{ return opt_key == "pcre" or opt_key == "regex" or opt_key == "sd_pattern"; }

static std::string escape(const std::string& s)
{
    std::string res;
    int quotes_first = 0;
    int quotes_last = std::count(s.begin(), s.end(), '"') - 1;
    int quotes_count = quotes_first;

    for ( auto it = s.begin(); it != s.end(); ++it )
    {
        switch ( *it )
        {
        case '"':
        {
            if ( ( quotes_count > quotes_first ) and ( quotes_count < quotes_last ) )
                res += "\\\"";
            else
                res += "\"";

            ++quotes_count;
            continue;
        }
        case '\\': res += "\\\\"; continue;
        case '\a': res += "\\a"; continue;
        case '\b': res += "\\b"; continue;
        case '\f': res += "\\f"; continue;
        case '\n': res += "\\n"; continue;
        case '\r': res += "\\r"; continue;
        case '\t': res += "\\t"; continue;
        case '\v': res += "\\v"; continue;
        }

        res += *it;
    }

    return res;
}

void parse_rule_opt_begin(SnortConfig* sc, const char* key)
{
    if ( s_ignore )
        return;

    if ( s_capture )
    {
        s_body += " ";
        s_body += key;
        s_body += ":";
    }
    IpsManager::option_begin(sc, key, rule_proto);
}

void parse_rule_opt_set(
    SnortConfig* sc, const char* key, const char* opt, const char* val)
{
    if ( s_ignore )
        return;

    assert(opt);
    assert(val);
    if ( s_capture )
    {
        s_body +=  is_already_escaped(key) ? opt : escape(opt);
        if ( *val )
        {
            s_body += " ";
            s_body += val;
        }
        s_body += ",";
    }
    IpsManager::option_set(sc, key, opt, val);
}

static void select_section(section_flags& otn_sects, section_flags sections)
{
    // The logic for choosing the right section is limited to rule options working on a single section or
    // on both header and body. Should be updated if other combinations are required.
    if ((otn_sects == section_to_flag(PS_TRAILER) and sections == section_to_flag(PS_BODY)) or
        (sections == section_to_flag(PS_TRAILER) and otn_sects == section_to_flag(PS_BODY)))
    {
        otn_sects = section_to_flag(PS_ERROR);
        return;
    }

    if (otn_sects < sections)
        otn_sects = sections;
}

void parse_rule_opt_end(SnortConfig* sc, const char* key, OptTreeNode* otn)
{
    if ( s_ignore )
        return;

    if ( s_capture )
    {
        s_body.erase(s_body.length()-1, 1);
        s_body += ";";
    }
    RuleOptType type = OPT_TYPE_MAX;
    IpsOption* ips = IpsManager::option_end(sc, otn, otn->snort_protocol_id, key, type);
    CursorActionType cat = ips ? ips->get_cursor_type() : CAT_NONE;

    if ( cat > CAT_ADJUST )
    {
        if ( cat != CAT_SET_RAW )
            otn->set_service_only();
        buf_is_set = true;
    }

    if ( type != OPT_TYPE_META )
        otn->num_detection_opts++;

    for (int i=0; i<OptTreeNode::SECT_DIR__MAX; i++)
    {
        section_flags sections = ips ? ips->get_pdu_section(i==OptTreeNode::SECT_TO_SRV) : section_to_flag(PS_NONE);
        // Rule option is using the cursor. The default buffer is pkt_data, belongs to BODY section
        if (!buf_is_set and ((cat == CAT_ADJUST) or (cat == CAT_READ)))
            sections = section_to_flag(PS_BODY);

        select_section(otn->sections[i], sections);
    }
}

OptTreeNode* parse_rule_open(SnortConfig* sc, RuleTreeNode& rtn, bool stub)
{
    if ( s_ignore )
        return nullptr;

    if ( stub )
    {
        parse_rule_proto(sc, "tcp", rtn, true);
        parse_rule_nets(sc, "any", true, rtn, true);
        parse_rule_ports(sc, "any", true, rtn, true);
        parse_rule_dir(sc, "->", rtn, true);
        parse_rule_nets(sc, "any", false, rtn, true);
        parse_rule_ports(sc, "any", false, rtn, true);
    }
    OptTreeNode* otn = new OptTreeNode;
    otn->state = new OtnState[ThreadConfig::get_instance_max()];

    otn->snort_protocol_id = rtn.snort_protocol_id;

    if ( sc->get_default_rule_state() or rule_is_stateless() )
        rtn.set_enabled();

    IpsManager::reset_options();

    s_capture = sc->dump_rule_meta();
    s_body = "(";
    buf_is_set = false;

    return otn;
}

static void parse_rule_state(SnortConfig* sc, const RuleTreeNode& rtn, OptTreeNode* otn)
{
    if ( otn->num_detection_opts )
    {
        ParseError("%u:%u rule state stubs do not support detection options",
            otn->sigInfo.gid, otn->sigInfo.sid);
    }
    RuleKey key =
    {
        snort::get_ips_policy()->policy_id,
        otn->sigInfo.gid,
        otn->sigInfo.sid
    };
    RuleState state =
    {
        s_type,
        rtn.action,
        otn->enable
    };
    sc->rule_states->add(key, state);

    if ( rtn.sip )
        sfvar_free(rtn.sip);
    if ( rtn.dip )
        sfvar_free(rtn.dip);

    delete otn;
}

static bool is_builtin(uint32_t gid)
{
    return ModuleManager::gid_in_use(gid) or
        ( gid >= GID_BUILTIN_MIN and gid <= GID_BUILTIN_MAX );
}

void parse_rule_close(SnortConfig* sc, RuleTreeNode& rtn, OptTreeNode* otn)
{
    if ( s_ignore )
    {
        s_ignore = false;
        skip_count++;
        return;
    }

    if ( otn->is_rule_state_stub() )
    {
        parse_rule_state(sc, rtn, otn);
        delete rtn.header;
        rtn.header = nullptr;
        return;
    }

    if ( !s_so_rule and !sc->metadata_filter.empty() and !otn->metadata_matched() )
    {
        delete otn;
        FreeRuleTreeNode(&rtn);
        ClearIpsOptionsVars();
        skip_count++;
        return;
    }

    if ( s_so_rule )
    {
        otn->sigInfo.gid = s_so_rule->gid;
        otn->sigInfo.sid = s_so_rule->sid;
        otn->sigInfo.rev = s_so_rule->rev;
    }
    else if ( otn->soid )
    {
        // for so rules, delete the otn and parse the actual rule
        // keep the stub's rtn to allow user tuning of nets and ports
        // if already entered, don't recurse again

        const char* rule = SoManager::get_so_rule(otn->soid, sc);
        IpsManager::reset_options();

        if ( !rule )
        {
            if ( sc->allow_missing_so_rules )
                ParseWarning(WARN_RULES, "SO rule %s not loaded.", otn->soid);
            else
                ParseError("SO rule %s not loaded.", otn->soid);

            FreeRuleTreeNode(&rtn);
        }
        else
        {
            SoRule so_rule(&rtn, otn);
            s_so_rule = &so_rule;
            parse_rules_string(sc, rule);
            s_so_rule = nullptr;
        }
        delete otn;
        return;
    }

    RuleTreeNode* tmp = s_so_rule ? s_so_rule->rtn : &rtn;
    RuleTreeNode* new_rtn = transfer_rtn(tmp);
    addRtnToOtn(sc, otn, new_rtn);

    OptTreeNode* otn_dup =
        OtnLookup(sc->otn_map, otn->sigInfo.gid, otn->sigInfo.sid);

    if ( otn_dup )
    {
        dup_count++;
        otn->ruleIndex = otn_dup->ruleIndex;

        if ( mergeDuplicateOtn(sc, otn_dup, otn, new_rtn) )
        {
            /* We are keeping the old/dup OTN and trashing the new one
             * we just created - it's freed in the remove dup function */
            return;
        }
    }
    else
    {
        otn_count++;
        rule_count++;
    }

    if ( otn->soid )
    {
        otn->sigInfo.builtin = false;
        if ( !otn_dup )
            so_rule_count++;
    }
    else if ( is_builtin(otn->sigInfo.gid) )
    {
        if ( otn->num_detection_opts )
            ParseError("%u:%u builtin rules do not support detection options",
                otn->sigInfo.gid, otn->sigInfo.sid);

        otn->sigInfo.builtin = true;
        if ( !otn_dup )
            builtin_rule_count++;
    }
    else
    {
        if ( !otn->num_detection_opts )
            ParseWarning(WARN_RULES, "%u:%u does not have any detection options",
                otn->sigInfo.gid, otn->sigInfo.sid);

        otn->sigInfo.builtin = false;
        if ( !otn_dup )
            detect_rule_count++;
    }

    if ( !otn_dup )
        otn->ruleIndex = parser_get_rule_index(otn->sigInfo.gid, otn->sigInfo.sid);

    if ( otn->sigInfo.message.empty() )
        otn->sigInfo.message = "\"no msg in rule\"";

    OptFpList* fpl = AddOptFuncToList(nullptr, otn);
    fpl->type = RULE_OPTION_TYPE_LEAF_NODE;

    if ( is_service_protocol(otn->snort_protocol_id) )
    {
        // copy required because the call to add_service_to_otn can
        // invalidate the service name pointer
        std::string service = sc->proto_ref->get_name(otn->snort_protocol_id);
        add_service_to_otn(sc, otn, service.c_str());
    }
    if (!otn->sigInfo.services.size() and action_file_id)
    {
        add_service_to_otn(sc, otn, "file_id");
        action_file_id = false;
    }

    validate_services(sc, otn);
    OtnLookupAdd(sc->otn_map, otn);

    if ( s_capture )
    {
        s_body += " )";
        otn->sigInfo.body = new std::string(s_body);
    }

    ClearIpsOptionsVars();

    for (int i=0; i<OptTreeNode::SECT_DIR__MAX; i++)
    {
        if (otn->sections[i] == section_to_flag(PS_HEADER_BODY))
            otn->sections[i] = section_to_flag(PS_HEADER) | section_to_flag(PS_BODY);
    }

    if ((otn->to_server_err() && otn->to_server()) ||
        (otn->to_client_err() && otn->to_client()) ||
        (otn->to_server_err() && otn->to_client_err()))
        ParseError("Rule cannot examine both HTTP message body and HTTP trailers, unless it is request"
            " trailer with response body");

}

void parse_rule_process_rtn(RuleTreeNode* rtn)
{
    if (rtn->sip->head && rtn->sip->head->flags & SFIP_ANY)
        rtn->flags |= RuleTreeNode::ANY_SRC_IP;
    else
        rtn->flags &= ~RuleTreeNode::ANY_SRC_IP;

    if (rtn->dip->head && rtn->dip->head->flags & SFIP_ANY)
        rtn->flags |= RuleTreeNode::ANY_DST_IP;
    else
        rtn->flags &= ~RuleTreeNode::ANY_DST_IP;

    ValidateIPList(rtn->sip, rtn->sip->name);
    ValidateIPList(rtn->dip, rtn->dip->name);

    if ( PortObjectHasAny(rtn->src_portobject) )
        rtn->flags |= RuleTreeNode::ANY_SRC_PORT;
    else
        rtn->flags &= ~RuleTreeNode::ANY_SRC_PORT;

    if ( PortObjectHasAny(rtn->dst_portobject) )
        rtn->flags |= RuleTreeNode::ANY_DST_PORT;
    else
        rtn->flags &= ~RuleTreeNode::ANY_DST_PORT;

    head_count++;
    SetupRTNFuncList(rtn);
}

/*
 * Finish adding the rule to the port tables
 *
 * 1) find the table this rule should belong to (src/dst/any-any tcp,udp,icmp,ip or nocontent)
 * 2) find an index for the gid:sid pair
 * 3) add all no content rules to a single no content port object, the ports are irrelevant so
 *    make it a any-any port object.
 * 4) if it's an any-any rule with content, add to an any-any port object
 * 5) find if we have a port object with these ports defined, if so get it, otherwise create it.
 *    a)do this for src and dst port
 *    b)add the rule index/id to the portobject(s)
 *    c)if the rule is bidir add the rule and port-object to both src and dst tables
 */
int parse_rule_finish_ports(SnortConfig* sc, RuleTreeNode* rtn, OptTreeNode* otn)
{
    RulePortTables* port_tables = sc->port_tables;
    FastPatternConfig* fp = sc->fast_pattern_config;

    int large_port_group = 0;
    PortTable* dstTable;
    PortTable* srcTable;
    PortObject* aaObject;
    rule_count_t* prc;
    uint32_t orig_flags = rtn->flags;

    /* Select the Target PortTable for this rule, based on protocol, src/dst
     * dir, and if there is rule content */
    switch ( otn->snort_protocol_id )
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
        rtn->flags |= RuleTreeNode::ANY_SRC_PORT|RuleTreeNode::ANY_DST_PORT;
        dstTable = srcTable = nullptr;
        aaObject = port_tables->svc_any;
        prc = &svcCnt;
    }

    if ( !rtn->any_src_port() and !rtn->any_dst_port() )
        prc->both++;

    int src_cnt = rtn->any_src_port() ? 65535 : PortObjectPortCount(rtn->src_portobject);
    int dst_cnt = rtn->any_dst_port() ? 65535 : PortObjectPortCount(rtn->dst_portobject);

    /* If not an any-any rule test for port bleedover, if we are using a
     * single rule group, don't bother */
    if ( !fp->get_single_rule_group() and !rtn->any_any_port() )
    {
        if (src_cnt >= fp->get_bleed_over_port_limit())
            ++large_port_group;

        if (dst_cnt >= fp->get_bleed_over_port_limit())
            ++large_port_group;

        if (large_port_group == 2 && fp->get_bleed_over_warnings())
        {
            LogMessage("***Bleedover Port Limit(%d) Exceeded for rule %u:%u "
                "(%d)ports: ", fp->get_bleed_over_port_limit(),
                otn->sigInfo.gid, otn->sigInfo.sid,
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
    if ( rtn->any_any_port() or large_port_group == 2 or fp->get_single_rule_group() )
    {
        if (otn->snort_protocol_id == SNORT_PROTO_IP)
        {
            PortObjectAddRule(port_tables->icmp.any, otn->ruleIndex);
            icmpCnt.any++;

            PortObjectAddRule(port_tables->tcp.any, otn->ruleIndex);
            tcpCnt.any++;

            PortObjectAddRule(port_tables->udp.any, otn->ruleIndex);
            udpCnt.any++;
        }
        /* For all protocols-add to the any any group */
        PortObjectAddRule(aaObject, otn->ruleIndex);
        prc->any++;
        rtn->flags = orig_flags;
        return 0; /* done */
    }

    bool both_dirs = false;

    /* add rule index to dst table if we have a specific dst port or port list */
    if ( dst_cnt < fp->get_bleed_over_port_limit() and dst_cnt <= src_cnt )
    {
        prc->dst++;

        /* find the proper port object */
        PortObject* pox = PortTableFindInputPortObjectPorts(dstTable, rtn->dst_portobject);
        if ( !pox )
        {
            /* Add the port object to the table, and add the rule to the port object */
            pox = PortObjectDupPorts(rtn->dst_portobject);
            PortTableAddObject(dstTable, pox);
        }

        PortObjectAddRule(pox, otn->ruleIndex);

        /* if bidir, add this rule and port group to the src table */
        if ( rtn->flags & RuleTreeNode::BIDIRECTIONAL )
        {
            pox = PortTableFindInputPortObjectPorts(srcTable, rtn->dst_portobject);
            if ( !pox )
            {
                pox = PortObjectDupPorts(rtn->dst_portobject);
                PortTableAddObject(srcTable, pox);
            }

            PortObjectAddRule(pox, otn->ruleIndex);
            both_dirs = true;
        }
    }

    /* add rule index to src table if we have a specific src port or port list */
    if ( src_cnt < fp->get_bleed_over_port_limit() and src_cnt < dst_cnt )
    {
        prc->src++;
        PortObject* pox = PortTableFindInputPortObjectPorts(srcTable, rtn->src_portobject);
        if ( !pox )
        {
            pox = PortObjectDupPorts(rtn->src_portobject);
            PortTableAddObject(srcTable, pox);
        }

        PortObjectAddRule(pox, otn->ruleIndex);

        /* if bidir, add this rule and port group to the dst table */
        if ( !both_dirs and rtn->flags & RuleTreeNode::BIDIRECTIONAL )
        {
            pox = PortTableFindInputPortObjectPorts(dstTable, rtn->src_portobject);
            if ( !pox )
            {
                pox = PortObjectDupPorts(rtn->src_portobject);
                PortTableAddObject(dstTable, pox);
            }
            PortObjectAddRule(pox, otn->ruleIndex);
        }
    }
    return 0;
}

void parse_rule_dec_head_count()
{
    head_count--;
}
