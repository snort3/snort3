//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// Major rewrite: Hui Cao <hcao@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_flowbits.h"

#include <forward_list>
#include <sstream>
#include <string>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/ghash.h"
#include "hash/hash_defs.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "utils/bitop.h"
#include "utils/sflsq.h"
#include "utils/util.h"

using namespace snort;

#define s_name "flowbits"

static THREAD_LOCAL ProfileStats flowBitsPerfStats;

#define ALLOWED_SPECIAL_CHARS       ".-_"

#define FLOWBITS_SET       0x01
#define FLOWBITS_UNSET     0x02
#define FLOWBITS_TOGGLE    0x04
#define FLOWBITS_ISSET     0x08
#define FLOWBITS_ISNOTSET  0x10
#define FLOWBITS_RESET     0x20
#define FLOWBITS_NOALERT   0x40
#define FLOWBITS_SETX      0x80

/**
**  The FLOWBITS_OBJECT is used to track the different
**  flowbit names that set/unset/etc. bits.  We use these
**  so that we can verify that the rules that use flowbits
**  make sense.
**
**  The types element tracks all the different operations that
**  may occur for a given object.  This is different from how
**  the type element is used from the FLOWBITS_OP structure.
*/
struct FLOWBITS_OBJECT
{
    uint16_t id = 0;
    uint8_t types = 0;
    int toggle = 0;
    int set = 0;
    int isset = 0;
};

typedef enum
{
    FLOWBITS_AND,
    FLOWBITS_OR,
    FLOWBITS_ANY,
    FLOWBITS_ALL
}Flowbits_eval;

/**
**  This class is the context ptr for each detection option
**  on a rule.  The id is associated with a FLOWBITS_OBJECT id.
**
**  The type element track only one operation.
*/
class FLOWBITS_OP
{
public:
    std::string name;
    std::string group;

    std::vector<uint16_t> ids;
    Flowbits_eval eval = FLOWBITS_AND;

    uint32_t group_id = 0;
    uint8_t type = 0;         /* Set, Unset, Invert, IsSet, IsNotSet, Reset  */
};

struct FLOWBITS_GRP
{
    std::string name;
    BitOp* GrpBitOp = nullptr;

    uint32_t group_id = 0;

    uint16_t count = 0;
    uint16_t max_id = 0;
};

struct FlowBitState
{
    std::forward_list<const FLOWBITS_OP*> op_list;
    GHash* flowbits_hash = nullptr;
    GHash* flowbits_grp_hash = nullptr;
    SF_QUEUE* flowbits_bit_queue = nullptr;
    unsigned flowbits_count = 0;
    unsigned flowbits_grp_count = 0;
    int flowbits_toggle = 1;
};

// Forward declarations
static void free_item(void*);
static void free_group(void*);

static IpsOption::EvalStatus check_flowbits(FLOWBITS_OP*, Packet*);

class FlowBitsOption : public IpsOption
{
public:
    FlowBitsOption(FLOWBITS_OP* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_FLOWBIT), config(c)
    { }

    ~FlowBitsOption() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    bool is_set(uint8_t bits)
    { return (config->type & bits) != 0; }

private:
    FLOWBITS_OP* config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

FlowBitsOption::~FlowBitsOption()
{
    delete config;
}

uint32_t FlowBitsOption::hash() const
{
    uint32_t a,b,c;
    const FLOWBITS_OP* data = config;
    unsigned i;
    unsigned j = 0;

    a = data->eval;
    b = data->type;
    c = 0;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    for (i = 0, j = 0; i < data->ids.size(); i++, j++)
    {
        if (j >= 3)
        {
            a += data->ids[i - 2];
            b += data->ids[i - 1];
            c += data->ids[i];
            mix(a,b,c);
            j -= 3;
        }
    }
    if (1 == j)
    {
        a += data->ids[data->ids.size() - 1];
        b += data->ids.size();
    }
    else if (2 == j)
    {
        a += data->ids[data->ids.size() - 2];
        b += data->ids[data->ids.size() - 1]|data->ids.size() << 16;
    }

    c += data->group_id;

    finalize(a,b,c);

    return c;
}

bool FlowBitsOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const FlowBitsOption& rhs = (const FlowBitsOption&)ips;

    if ( (config->ids.size() != rhs.config->ids.size()) or
            (config->eval != rhs.config->eval) or
            (config->type != rhs.config->type) or
            (config->group_id != rhs.config->group_id) )
        return false;

    for ( unsigned i = 0; i < config->ids.size(); i++ )
    {
        if (config->ids[i] != rhs.config->ids[i])
            return false;
    }

    return true;
}

IpsOption::EvalStatus FlowBitsOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(flowBitsPerfStats);
    return check_flowbits(config, p);
}

//-------------------------------------------------------------------------
// helper methods
//-------------------------------------------------------------------------

static inline BitOp* get_flow_bitop(const Packet* p, FlowBitState* flowbit_state)
{
    Flow* flow = p->flow;

    if (!flow)
        return nullptr;

    if ( !flow->bitop )
        flow->bitop = new BitOp(flowbit_state->flowbits_count);

    return flow->bitop;
}

static inline int clear_group_bit(
    BitOp* bitop, const std::string& group, FlowBitState* flowbit_state)
{
    if ( group.empty() )
        return 0;

    // FIXIT-M why is the hash lookup done at runtime for flowbits groups?
    // a pointer to flowbits_grp should be in flowbits config data
    // this *should* be safe but iff splay mode is disabled
    auto flowbits_grp = (FLOWBITS_GRP*)flowbit_state->flowbits_grp_hash->find(group.c_str());

    if ( !flowbits_grp )
        return 0;

    if ( !bitop or (bitop->size() <= flowbits_grp->max_id) or !flowbits_grp->count )
        return 0;

    auto GrpBitOp = flowbits_grp->GrpBitOp;

    /* note, max_id is an index, not a count.
     * Calculate max_bytes by adding 8 to max_id, then dividing by 8.  */
    unsigned int max_bytes = (flowbits_grp->max_id + 8) >> 3;

    for ( unsigned int i = 0; i < max_bytes; i++ )
        bitop->get_buf_element(i) &= ~GrpBitOp->get_buf_element(i);

    return 1;
}

static inline int toggle_group_bit(
    BitOp* bitop, const std::string& group, FlowBitState* flowbit_state)
{
    if ( group.empty() )
        return 0;

    auto flowbits_grp = (FLOWBITS_GRP*)flowbit_state->flowbits_grp_hash->find(group.c_str());

    if ( !flowbits_grp )
        return 0;

    if ( !bitop or  (bitop->size() <= flowbits_grp->max_id) or  !flowbits_grp->count )
        return 0;

    auto GrpBitOp = flowbits_grp->GrpBitOp;

    /* note, max_id is an index, not a count.
     * Calculate max_bytes by adding 8 to max_id, then dividing by 8.  */
    unsigned int max_bytes = (flowbits_grp->max_id + 8) >> 3;
    for ( unsigned int i = 0; i < max_bytes; i++ )
        bitop->get_buf_element(i) ^= GrpBitOp->get_buf_element(i);

    return 1;
}

static inline int set_xbits_to_group(
    BitOp* bitop, FLOWBITS_OP* fb, FlowBitState* flowbit_state)
{
    if ( !clear_group_bit(bitop, fb->group, flowbit_state) )
        return 0;

    for ( auto id : fb->ids )
        bitop->set(id);

    return 1;
}

static inline int is_set_flowbits(
    BitOp* bitop, FLOWBITS_OP* fb, FlowBitState* flowbit_state)
{
    FLOWBITS_GRP* flowbits_grp;

    switch ( fb->eval )
    {
    case FLOWBITS_AND:
        for ( auto id : fb->ids )
        {
            if ( !bitop->is_set(id) )
                return 0;
        }
        return 1;

    case FLOWBITS_OR:
        for ( auto id : fb->ids )
        {
            if ( bitop->is_set(id) )
                return 1;
        }
        return 0;

    case FLOWBITS_ALL:
        flowbits_grp = (FLOWBITS_GRP*)flowbit_state->flowbits_grp_hash->find(fb->group.c_str());

        if ( !flowbits_grp )
            return 0;

        for ( unsigned i = 0; i <= (unsigned int)(flowbits_grp->max_id >>3); i++ )
        {
            uint8_t val = bitop->get_buf_element(i) & flowbits_grp->GrpBitOp->get_buf_element(i);

            if ( val != flowbits_grp->GrpBitOp->get_buf_element(i) )
                return 0;
        }
        return 1;

    case FLOWBITS_ANY:
        flowbits_grp = (FLOWBITS_GRP*)flowbit_state->flowbits_grp_hash->find(fb->group.c_str());

        if ( !flowbits_grp )
            return 0;

        for ( unsigned i = 0; i <= (unsigned int)(flowbits_grp->max_id >>3); i++ )
        {
            uint8_t val = bitop->get_buf_element(i) & flowbits_grp->GrpBitOp->get_buf_element(i);
            if ( val )
                return 1;
        }
        return 0;

    default:
        return 0;
    }
}

static IpsOption::EvalStatus check_flowbits(FLOWBITS_OP* fb, Packet* p)
{
    int result = 0;

    FlowBitState* flowbit_state = SnortConfig::get_conf()->flowbit_state;
    assert(flowbit_state != nullptr);

    BitOp* bitop = get_flow_bitop(p, flowbit_state);
    if (!bitop)
        return IpsOption::NO_MATCH;

    switch (fb->type)
    {
    case FLOWBITS_SET:
        for ( auto id : fb->ids )
            bitop->set(id);
        result = 1;
        break;

    case FLOWBITS_SETX:
        result = set_xbits_to_group(bitop, fb, flowbit_state);
        break;

    case FLOWBITS_UNSET:
        if (fb->eval == FLOWBITS_ALL )
            clear_group_bit(bitop, fb->group, flowbit_state);
        else
        {
            for ( auto id : fb->ids )
                bitop->clear(id);
        }
        result = 1;
        break;

    case FLOWBITS_RESET:
        if ( fb->group.empty() )
            bitop->reset();
        else
            clear_group_bit(bitop, fb->group, flowbit_state);

        result = 1;
        break;

    case FLOWBITS_ISSET:
        if ( is_set_flowbits(bitop, fb, flowbit_state) )
            result = 1;
        else
            return IpsOption::FAILED_BIT;
        break;

    case FLOWBITS_ISNOTSET:
        if ( !is_set_flowbits(bitop, fb, flowbit_state) )
            result = 1;
        else
            return IpsOption::FAILED_BIT;
        break;

    case FLOWBITS_TOGGLE:
        if ( !fb->group.empty() )
            toggle_group_bit(bitop, fb->group, flowbit_state);

        else for ( auto id : fb->ids )
        {
            if (bitop->is_set(id))
                bitop->clear(id);
            else
                bitop->set(id);
        }
        result = 1;

        break;

    case FLOWBITS_NOALERT:
        /*
         **  This logic allows us to put flowbits: noalert any where
         **  in the detection chain, and still do bit ops after this
         **  option.
         */
        return IpsOption::NO_ALERT;

    default:
        return IpsOption::NO_MATCH;
    }

    if (result == 1)
        return IpsOption::MATCH;

    return IpsOption::NO_MATCH;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------
void flowbits_ginit(SnortConfig* sc)
{
    sc->flowbit_state = new FlowBitState;
    sc->flowbit_state->flowbits_hash = new GHash(10000, 0, 0, free_item);

    // this is used during parse time and runtime so do NOT
    // enable splay mode (which is NOT useful here anyway)
    sc->flowbit_state->flowbits_grp_hash = new GHash(10000, 0, 0, free_group);
    sc->flowbit_state->flowbits_bit_queue = sfqueue_new();
}

void flowbits_gterm(SnortConfig* sc)
{
    FlowBitState* flowbit_state = sc->flowbit_state;
    if (flowbit_state == nullptr)
        return;

    if ( flowbit_state->flowbits_hash )
        delete flowbit_state->flowbits_hash;

    if ( flowbit_state->flowbits_grp_hash )
        delete flowbit_state->flowbits_grp_hash;

    if ( flowbit_state->flowbits_bit_queue )
        sfqueue_free_all(flowbit_state->flowbits_bit_queue, nullptr);

    delete flowbit_state;
    flowbit_state = nullptr;
}

int FlowBits_SetOperation(void* option_data)
{
    FlowBitsOption* p = (FlowBitsOption*)option_data;

    if (p->is_set(FLOWBITS_SET | FLOWBITS_SETX |FLOWBITS_UNSET | FLOWBITS_TOGGLE |
        FLOWBITS_RESET))
    {
        return 1;
    }
    return 0;
}

//-------------------------------------------------------------------------
// parsing methods
//-------------------------------------------------------------------------

static bool validate_name(const char* name)
{
    assert(name);

    for ( unsigned i=0; i<strlen(name); i++ )
    {
        if (!isalnum(name[i]) and (nullptr == strchr(ALLOWED_SPECIAL_CHARS,name[i])))
            return false;
    }
    return true;
}

static FLOWBITS_OBJECT* get_item(
    const char* bit, FLOWBITS_OP* flowbits, FlowBitState* flowbit_state)
{
    if ( !validate_name(bit) )
    {
        ParseAbort("%s: name is limited to any alphanumeric string including %s",
            s_name, ALLOWED_SPECIAL_CHARS);
    }

    FLOWBITS_OBJECT* flowbits_item = (FLOWBITS_OBJECT*)flowbit_state->flowbits_hash->find(bit);

    if ( !flowbits_item )
    {
        flowbits_item = new FLOWBITS_OBJECT;

        if (sfqueue_count(flowbit_state->flowbits_bit_queue) > 0)
        {
            flowbits_item->id = (uint16_t)(uintptr_t)sfqueue_remove(
                flowbit_state->flowbits_bit_queue);
        }
        else
        {
            flowbits_item->id = flowbit_state->flowbits_count++;

            if ( !flowbit_state->flowbits_count )
            {
                ParseError("The number of flowbit IDs in the current ruleset exceeds "
                    "the maximum number of IDs that are allowed (%u).",
                    flowbit_state->flowbits_count-1);
            }
        }

        int hstatus = flowbit_state->flowbits_hash->insert(bit, flowbits_item);

        if (hstatus != HASH_OK)
            ParseError("Could not add flowbits key (%s) to hash.", bit);
    }
    flowbits_item->toggle = flowbit_state->flowbits_toggle;
    flowbits_item->types |= flowbits->type;

    switch (flowbits->type)
    {
    case FLOWBITS_SET:
    case FLOWBITS_SETX:
    case FLOWBITS_UNSET:
    case FLOWBITS_TOGGLE:
    case FLOWBITS_RESET:
        flowbits_item->set++;
        break;
    case FLOWBITS_ISSET:
    case FLOWBITS_ISNOTSET:
        flowbits_item->isset++;
        break;
    default:
        break;
    }

    return flowbits_item;
}

static void parse_flowbits(
    const char* flowbits_names, FLOWBITS_OP* flowbits, FlowBitState* flowbit_state)
{
    FLOWBITS_OBJECT* flowbits_item;

    if ( !flowbits_names or  ((*flowbits_names) == 0) )
        return;

    if ( strchr(flowbits_names, '|') )
    {
        if ( strchr(flowbits_names, '&') )
        {
            ParseError("%s: tag id opcode '|' and '&' are used together.", s_name);
            return;
        }
        std::string bits = flowbits_names;
        std::replace(bits.begin(), bits.end(), '|', ' ');
        std::stringstream ss(bits);
        std::string tok;

        while ( ss >> tok )
        {
            flowbits_item = get_item(tok.c_str(), flowbits, flowbit_state);
            flowbits->ids.push_back(flowbits_item->id);
        }
        flowbits->eval = FLOWBITS_OR;
    }
    else if ( strchr(flowbits_names, '&') )
    {
        std::string bits = flowbits_names;
        std::replace(bits.begin(), bits.end(), '&', ' ');
        std::stringstream ss(bits);
        std::string tok;

        while ( ss >> tok )
        {
            flowbits_item = get_item(tok.c_str(), flowbits, flowbit_state);
            flowbits->ids.push_back(flowbits_item->id);
        }
        flowbits->eval = FLOWBITS_AND;
    }
    else if ( !strcasecmp(flowbits_names, "all") )
    {
        flowbits->eval = FLOWBITS_ALL;
    }
    else if ( !strcasecmp(flowbits_names, "any") )
    {
        flowbits->eval = FLOWBITS_ANY;
    }
    else
    {
        flowbits_item = get_item(flowbits_names, flowbits, flowbit_state);
        flowbits->ids.push_back(flowbits_item->id);
    }
}

static void validateFlowbitsSyntax(FLOWBITS_OP* flowbits)
{
    switch (flowbits->type)
    {
    case FLOWBITS_SET:
        if ( (flowbits->eval == FLOWBITS_AND) and !flowbits->ids.empty() )
            break;

        ParseError("%s: operation set uses syntax: flowbits:set,bit[&bit],[group].", s_name);
        return;

    case FLOWBITS_SETX:
        if ( (flowbits->eval == FLOWBITS_AND) and !flowbits->group.empty() and
            !flowbits->ids.empty() )
            break;

        ParseError("%s: operation setx uses syntax: flowbits:setx,bit[&bit],group.", s_name);
        return;

    case FLOWBITS_UNSET:
        if (((flowbits->eval == FLOWBITS_AND) and flowbits->group.empty() and !flowbits->ids.empty())
            or ((flowbits->eval == FLOWBITS_ALL) and !flowbits->group.empty()))
            break;

        ParseError("%s: operation unset uses syntax: flowbits:unset,bit[&bit] OR"
            " flowbits:unset, all, group.", s_name);
        return;

    case FLOWBITS_TOGGLE:
        if (((flowbits->eval == FLOWBITS_AND) and flowbits->group.empty() and !flowbits->ids.empty())
            or ((flowbits->eval == FLOWBITS_ALL) and !flowbits->group.empty()))
            break;

        ParseError("%s: operation toggle uses syntax: flowbits:toggle,bit[&bit] OR"
            " flowbits:toggle,all,group.", s_name);
        return;

    case FLOWBITS_ISSET:
        if ((((flowbits->eval == FLOWBITS_AND) or (flowbits->eval == FLOWBITS_OR)) and
            flowbits->group.empty() and !flowbits->ids.empty())
            or (((flowbits->eval == FLOWBITS_ANY) or (flowbits->eval == FLOWBITS_ALL)) and
            !flowbits->group.empty()))
            break;

        ParseError("%s: operation isset uses syntax: flowbits:isset,bit[&bit] OR "
            "flowbits:isset,bit[|bit] OR flowbits:isset,all,group OR flowbits:isset,any,group.",
            s_name);
        return;

    case FLOWBITS_ISNOTSET:
        if ((((flowbits->eval == FLOWBITS_AND) or  (flowbits->eval == FLOWBITS_OR)) and
            flowbits->group.empty() and !flowbits->ids.empty())
            or ((((flowbits->eval == FLOWBITS_ANY)) or (flowbits->eval == FLOWBITS_ALL)) and
            !flowbits->group.empty()))
            break;

        ParseError("%s: operation isnotset uses syntax: flowbits:isnotset,bit[&bit] OR "
            "flowbits:isnotset,bit[|bit] OR flowbits:isnotset,all,group OR "
            "flowbits:isnotset,any,group.", s_name);
        return;

    case FLOWBITS_RESET:
        if ( flowbits->ids.empty() )
            break;

        ParseError(
            "%s: operation unset uses syntax: flowbits:reset OR flowbits:reset, group.", s_name);
        return;

    case FLOWBITS_NOALERT:
        if ( flowbits->ids.empty() and flowbits->group.empty() )
            break;

        ParseError("%s: operation noalert uses syntax: flowbits:noalert.", s_name);
        return;

    default:
        ParseError("%s: unknown opcode.", s_name);
        return;
    }
}

static FLOWBITS_GRP* get_group(const char* group, FlowBitState* flowbit_state)
{
    if (!validate_name(group))
    {
        ParseAbort(
            "%s: flowbits group name is limited to any alphanumeric string including %s",
            s_name, ALLOWED_SPECIAL_CHARS);
    }

    FLOWBITS_GRP* flowbits_grp = (FLOWBITS_GRP*)flowbit_state->flowbits_grp_hash->find(group);

    if ( !flowbits_grp )
    {
        // new group defined, add (bitop set later once we know size)
        flowbits_grp = new FLOWBITS_GRP;
        flowbit_state->flowbits_grp_hash->insert(group, flowbits_grp);
        flowbit_state->flowbits_grp_count++;
        flowbits_grp->group_id = flowbit_state->flowbits_grp_count;
        flowbits_grp->name = group;
    }

    return flowbits_grp;
}

static void parse_flowbits_with_group(
    const char* bits, const char* group, FLOWBITS_OP* flowbits, FlowBitState* flowbit_state)
{
    parse_flowbits(bits, flowbits, flowbit_state);

    if ( group and flowbits->group.empty() )
    {
        flowbits->group = group;
        FLOWBITS_GRP* flowbits_grp = get_group(group, flowbit_state);
        flowbits->group_id = flowbits_grp->group_id;
    }
    validateFlowbitsSyntax(flowbits);

    if ( !flowbits->group.empty() )
        flowbit_state->op_list.push_front(flowbits);
}

static FLOWBITS_OP* flowbits_parse(
    std::string& op, std::string& bits, std::string& group, SnortConfig* sc)
{
    FlowBitState* flowbit_state = sc->flowbit_state;
    assert(flowbit_state != nullptr);

    FLOWBITS_OP* flowbits = new FLOWBITS_OP;
    flowbits->name = op;

    if ( op == "set" )
        flowbits->type = FLOWBITS_SET;

    else if ( op == "setx" )
        flowbits->type = FLOWBITS_SETX;

    else if ( op == "unset" )
        flowbits->type = FLOWBITS_UNSET;

    else if ( op == "toggle" )
        flowbits->type = FLOWBITS_TOGGLE;

    else if ( op == "isset" )
        flowbits->type = FLOWBITS_ISSET;

    else if ( op == "isnotset" )
        flowbits->type = FLOWBITS_ISNOTSET;

    else if ( op == "noalert" )
    {
        if ( !bits.empty() )
        {
            ParseError("%s: invalid configuration.", s_name);
            delete flowbits;
            return nullptr;
        }

        flowbits->type = FLOWBITS_NOALERT;
        return flowbits;
    }
    else if ( op == "reset" )
    {
        if ( !group.empty() )
        {
            ParseError("%s: invalid configuration.", s_name);
            delete flowbits;
            return nullptr;
        }
        if ( !bits.empty() )
        {
            group = bits;
            FLOWBITS_GRP* flowbits_grp = get_group(group.c_str(), flowbit_state);
            flowbits->group = group;
            flowbits->group_id = flowbits_grp->group_id;
        }
        flowbits->type = FLOWBITS_RESET;
        return flowbits;
    }
    else
    {
        ParseError("%s: invalid configuration.", s_name);
        delete flowbits;
        return nullptr;
    }

    parse_flowbits_with_group(bits.c_str(), group.c_str(), flowbits, flowbit_state);
    return flowbits;
}

static void update_group(FLOWBITS_GRP* flowbits_grp, int id)
{
    flowbits_grp->count++;

    if ( flowbits_grp->max_id < id )
        flowbits_grp->max_id = id;

    flowbits_grp->GrpBitOp->set(id);
}

static void init_groups(FlowBitState* flowbit_state)
{
    if ( !flowbit_state->flowbits_hash or !flowbit_state->flowbits_grp_hash )
        return;

    for (GHashNode* n = flowbit_state->flowbits_grp_hash->find_first();
         n != nullptr;
         n= flowbit_state->flowbits_grp_hash->find_next())
    {
        FLOWBITS_GRP* fbg = (FLOWBITS_GRP*)n->data;
        fbg->GrpBitOp = new BitOp(flowbit_state->flowbits_count);
        fbg->GrpBitOp->reset();
    }

    while ( !flowbit_state->op_list.empty() )
    {
        const FLOWBITS_OP* fbop = flowbit_state->op_list.front();
        FLOWBITS_GRP* fbg =
            (FLOWBITS_GRP*)flowbit_state->flowbits_grp_hash->find(fbop->group.c_str());
        assert(fbg);

        for ( unsigned i = 0; i < fbop->ids.size(); ++i )
            update_group(fbg, fbop->ids[i]);

        flowbit_state->op_list.pop_front();
    }
}

static void flowbits_verify(FlowBitState* flowbit_state)
{
    GHashNode* n;
    unsigned num_flowbits = 0;
    unsigned unchecked = 0, unset = 0;

    if (flowbit_state->flowbits_hash == nullptr)
        return;

    for (n = flowbit_state->flowbits_hash->find_first();
         n != nullptr;
         n = flowbit_state->flowbits_hash->find_next())
    {
        FLOWBITS_OBJECT* fb = (FLOWBITS_OBJECT*)n->data;

        if (fb->toggle != flowbit_state->flowbits_toggle)
        {
            sfqueue_add(flowbit_state->flowbits_bit_queue, (NODE_DATA)(uintptr_t)fb->id);
            flowbit_state->flowbits_hash->remove(n->key);
            continue;
        }

        if ((fb->set > 0) and (fb->isset == 0))
        {
            ParseWarning(WARN_FLOWBITS, "%s key '%s' is set but not checked.",
                s_name, (const char*)n->key);
            unchecked++;
        }
        else if ((fb->isset > 0) and (fb->set == 0))
        {
            ParseWarning(WARN_FLOWBITS, "%s key '%s' is checked but not ever set.",
                s_name, (const char*)n->key);
            unset++;
        }
        else if ((fb->set == 0) and (fb->isset == 0))
        {
            continue; /* don't count this bit as used */
        }

        num_flowbits++;
    }
    assert(num_flowbits == flowbit_state->flowbits_count);

    flowbit_state->flowbits_toggle ^= 1;

    if ( !num_flowbits )
        return;

    LogLabel(s_name);
    LogCount("defined", num_flowbits);
    LogCount("not checked", unchecked);
    LogCount("not set", unset);
}

static void free_item(void* d)
{
    FLOWBITS_OBJECT* data = (FLOWBITS_OBJECT*)d;
    delete data;
}

static void free_group(void* d)
{
    FLOWBITS_GRP* data = (FLOWBITS_GRP*)d;

    if (data->GrpBitOp)
        delete data->GrpBitOp;

    delete data;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~op", Parameter::PT_STRING, nullptr, nullptr,
      "set|reset|isset|etc." },  // FIXIT-L replace this legacy flowbits parsing with PT_SELECT

    { "~bits", Parameter::PT_STRING, nullptr, nullptr,
      "bits or group" },

    { "~group", Parameter::PT_STRING, nullptr, nullptr,
      "group if arg1 is bits" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to set and test arbitrary boolean flags"

class FlowbitsModule : public Module
{
public:
    FlowbitsModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &flowBitsPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

    FLOWBITS_OP* get_data();

public:
    std::string op;
    std::string bits;
    std::string group;
    FLOWBITS_OP* fbop = nullptr;
};

bool FlowbitsModule::begin(const char*, int, SnortConfig*)
{
    op.clear();
    bits.clear();
    group.clear();
    return true;
}

bool FlowbitsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~op") )
        op = v.get_string();

    else if ( v.is("~bits") )
        bits = v.get_string();

    else if ( v.is("~group") )
        group = v.get_string();

    else
        return false;

    return true;
}

bool FlowbitsModule::end(const char*, int, SnortConfig* sc)
{
    if ( op.empty() )
        return false;

    fbop = flowbits_parse(op, bits, group, sc);
    return fbop != nullptr;
}

FLOWBITS_OP* FlowbitsModule::get_data()
{
    FLOWBITS_OP* tmp = fbop;
    fbop = nullptr;
    return tmp;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FlowbitsModule;
}

static void mod_dtor(Module* m)
{
    FlowbitsModule* fb = (FlowbitsModule*)m;
    if (fb->fbop)
        delete fb->fbop;

    delete fb;
}

static IpsOption* flowbits_ctor(Module* p, OptTreeNode*)
{
    FlowbitsModule* m = (FlowbitsModule*)p;
    FLOWBITS_OP* fbop = m->get_data();
    return new FlowBitsOption(fbop);
}

static void flowbits_dtor(IpsOption* p)
{
    delete p;
}

static void flowbits_verify(SnortConfig* sc)
{
    FlowBitState* flowbit_state = sc->flowbit_state;
    init_groups(flowbit_state);
    flowbits_verify(flowbit_state);
}

#if 0
// FIXIT-M if add_detection_option() finds a dup, then
// we can leak the original group name if same as current
// also, why use new group name instead of original?
char* group_name =  ((FLOWBITS_OP*)idx_dup)->group;

if (flowbits->group)
{
    if (group_name and strcmp(group_name, flowbits->group))
        snort_free(group_name);
    ((FLOWBITS_OP*)idx_dup)->group = snort_strdup(flowbits->group);
}
// ... then delete current and use original
#endif

static const IpsApi flowbits_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    flowbits_ctor,
    flowbits_dtor,
    flowbits_verify
};

const BaseApi* ips_flowbits = &flowbits_api.base;

