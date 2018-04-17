//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

/*
 ** Major rewrite: Hui Cao <hcao@sourcefire.com>
 **
 ** Add flowbits OR support
 **
 ** sp_flowbits
 **
 ** Purpose:
 **
 ** Wouldn't it be nice if we could do some simple state tracking
 ** across multiple packets?  Well, this allows you to do just that.
 **
 ** Effect:
 **
 ** - [Un]set a bitmask stored with the session
 ** - Check the value of the bitmask
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_flowbits.h"

#include <forward_list>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/ghash.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "parser/mstring.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "utils/bitop.h"
#include "utils/sflsq.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

#define s_name "flowbits"

static THREAD_LOCAL ProfileStats flowBitsPerfStats;

#define DEFAULT_FLOWBIT_GROUP  "default"
#define ALLOWED_SPECIAL_CHARS       ".-_"

#define DEFAULT_FLOWBIT_SIZE  1024
#define MAX_FLOWBIT_SIZE      2048

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
    uint16_t id;
    uint8_t types;
    int toggle;
    int set;
    int isset;
};

typedef enum
{
    FLOWBITS_AND,
    FLOWBITS_OR,
    FLOWBITS_ANY,
    FLOWBITS_ALL
}Flowbits_eval;

/**
**  This structure is the context ptr for each detection option
**  on a rule.  The id is associated with a FLOWBITS_OBJECT id.
**
**  The type element track only one operation.
*/
struct FLOWBITS_OP
{
    uint16_t* ids;
    uint8_t num_ids;
    uint8_t type;         /* Set, Unset, Invert, IsSet, IsNotSet, Reset  */
    Flowbits_eval eval;   /* and , or, all, any*/
    char* name;
    char* group;
    uint32_t group_id;
};

typedef struct _FLOWBITS_GRP
{
    uint16_t count;
    uint16_t max_id;
    char* name;
    uint32_t group_id;
    BitOp* GrpBitOp;
} FLOWBITS_GRP;

static std::forward_list<const FLOWBITS_OP*> op_list;

static GHash* flowbits_hash = nullptr;
static GHash* flowbits_grp_hash = nullptr;
static SF_QUEUE* flowbits_bit_queue = nullptr;

static unsigned flowbits_count = 0;
static unsigned flowbits_grp_count = 0;
static int flowbits_toggle = 1;

static IpsOption::EvalStatus check_flowbits(
    uint8_t type, uint8_t evalType, uint16_t* ids, uint16_t num_ids,
    char* group, Packet* p);

class FlowBitsOption : public IpsOption
{
public:
    FlowBitsOption(FLOWBITS_OP* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_FLOWBIT)
    { config = c; }

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
    if (config->ids)
        snort_free(config->ids);
    if (config->name)
        snort_free(config->name);
    if (config->group)
        snort_free(config->group);

    snort_free(config);
}

uint32_t FlowBitsOption::hash() const
{
    uint32_t a,b,c;
    const FLOWBITS_OP* data = config;
    int i;
    int j = 0;

    a = data->eval;
    b = data->type;
    c = 0;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    for (i = 0, j = 0; i < data->num_ids; i++, j++)
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
        a += data->ids[data->num_ids - 1];
        b += data->num_ids;
    }
    else if (2 == j)
    {
        a += data->ids[data->num_ids - 2];
        b += data->ids[data->num_ids - 1]|data->num_ids << 16;
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

    if ( (config->num_ids != rhs.config->num_ids) or
        (config->eval != rhs.config->eval) or
        (config->type != rhs.config->type) or
        (config->group_id != rhs.config->group_id) )
        return false;

    for ( int i = 0; i < config->num_ids; i++ )
    {
        if (config->ids[i] != rhs.config->ids[i])
            return false;
    }

    return true;
}

IpsOption::EvalStatus FlowBitsOption::eval(Cursor&, Packet* p)
{
    Profile profile(flowBitsPerfStats);

    FLOWBITS_OP* flowbits = config;

    if (!flowbits)
        return NO_MATCH;


    return check_flowbits(flowbits->type, (uint8_t)flowbits->eval,
        flowbits->ids, flowbits->num_ids, flowbits->group, p);
}

//-------------------------------------------------------------------------
// helper methods
//-------------------------------------------------------------------------

static inline BitOp* get_flow_bitop(const Packet* p)
{
    Flow* flow = p->flow;

    if (!flow)
        return nullptr;

    if ( !flow->bitop )
        flow->bitop = new BitOp(flowbits_count);

    return flow->bitop;
}

static inline int clear_group_bit(BitOp* bitop, char* group)
{
    if ( !group )
        return 0;

    // FIXIT-M why is the hash lookup done at runtime for flowbits groups?
    // a pointer to flowbis_grp should be in flowbits config data
    // this *should* be safe but iff splay mode is disabled
    auto flowbits_grp = (FLOWBITS_GRP*)ghash_find(flowbits_grp_hash, group);

    if ( !flowbits_grp )
        return 0;

    if ( !bitop || (bitop->size() <= flowbits_grp->max_id) || !flowbits_grp->count )
        return 0;

    auto GrpBitOp = flowbits_grp->GrpBitOp;

    /* note, max_id is an index, not a count.
     * Calculate max_bytes by adding 8 to max_id, then dividing by 8.  */
    unsigned int max_bytes = (flowbits_grp->max_id + 8) >> 3;
    for ( unsigned int i = 0; i < max_bytes; i++ )
        bitop->get_buf_element(i) &= ~GrpBitOp->get_buf_element(i);

    return 1;
}

static inline int toggle_group_bit(BitOp* bitop, char* group)
{
    if ( !group  )
        return 0;

    auto flowbits_grp = (FLOWBITS_GRP*)ghash_find(flowbits_grp_hash, group);

    if ( !flowbits_grp )
        return 0;

    if ( !bitop || (bitop->size() <= flowbits_grp->max_id) || !flowbits_grp->count )
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
    BitOp* bitop, uint16_t* ids, uint16_t num_ids, char* group)
{
    unsigned int i;
    if (!clear_group_bit(bitop, group))
        return 0;
    for (i = 0; i < num_ids; i++)
        bitop->set(ids[i]);
    return 1;
}

static inline int is_set_flowbits(
    BitOp* bitop, uint8_t eval, uint16_t* ids,
    uint16_t num_ids, char* group)
{
    unsigned int i;
    FLOWBITS_GRP* flowbits_grp;
    Flowbits_eval evalType = (Flowbits_eval)eval;

    switch (evalType)
    {
    case FLOWBITS_AND:
        for (i = 0; i < num_ids; i++)
        {
            if (!bitop->is_set(ids[i]))
                return 0;
        }
        return 1;

    case FLOWBITS_OR:
        for (i = 0; i < num_ids; i++)
        {
            if (bitop->is_set(ids[i]))
                return 1;
        }
        return 0;

    case FLOWBITS_ALL:
        flowbits_grp = (FLOWBITS_GRP*)ghash_find(flowbits_grp_hash, group);
        if ( flowbits_grp == nullptr )
            return 0;
        for ( i = 0; i <= (unsigned int)(flowbits_grp->max_id >>3); i++ )
        {
            uint8_t val = bitop->get_buf_element(i) & flowbits_grp->GrpBitOp->get_buf_element(i);

            if ( val != flowbits_grp->GrpBitOp->get_buf_element(i) )
                return 0;
        }
        return 1;

    case FLOWBITS_ANY:
        flowbits_grp = (FLOWBITS_GRP*)ghash_find(flowbits_grp_hash, group);
        if ( flowbits_grp == nullptr )
            return 0;
        for ( i = 0; i <= (unsigned int)(flowbits_grp->max_id >>3); i++ )
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

static IpsOption::EvalStatus check_flowbits(
    uint8_t type, uint8_t evalType, uint16_t* ids, uint16_t num_ids, char* group, Packet* p)
{
    Flowbits_eval eval = (Flowbits_eval)evalType;
    int result = 0;
    int i;

    BitOp* bitop = get_flow_bitop(p);

    if (!bitop)
        return IpsOption::NO_MATCH;

    switch (type)
    {
    case FLOWBITS_SET:
        for (i = 0; i < num_ids; i++)
            bitop->set(ids[i]);
        result = 1;
        break;

    case FLOWBITS_SETX:
        result = set_xbits_to_group(bitop, ids, num_ids, group);
        break;

    case FLOWBITS_UNSET:
        if (eval == FLOWBITS_ALL )
            clear_group_bit(bitop, group);
        else
        {
            for (i = 0; i < num_ids; i++)
                bitop->clear(ids[i]);
        }
        result = 1;
        break;

    case FLOWBITS_RESET:
        if (!group)
            bitop->reset();
        else
            clear_group_bit(bitop, group);
        result = 1;
        break;

    case FLOWBITS_ISSET:

        if (is_set_flowbits(bitop,(uint8_t)eval, ids, num_ids, group))
        {
            result = 1;
        }
        else
        {
            return IpsOption::FAILED_BIT;
        }

        break;

    case FLOWBITS_ISNOTSET:
        if (!is_set_flowbits(bitop, (uint8_t)eval, ids, num_ids, group))
        {
            result = 1;
        }
        else
        {
            return IpsOption::FAILED_BIT;
        }
        break;

    case FLOWBITS_TOGGLE:
        if (group)
            toggle_group_bit(bitop, group);
        else
        {
            for (i = 0; i < num_ids; i++)
            {
                if (bitop->is_set(ids[i]))
                {
                    bitop->clear(ids[i]);
                }
                else
                {
                    bitop->set(ids[i]);
                }
            }
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
        /*
         **  Always return failure here.
         */
        return IpsOption::NO_MATCH;
    }

    /*
     **  Now return what we found
     */
    if (result == 1)
    {
        return IpsOption::MATCH;
    }

    return IpsOption::NO_MATCH;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void FlowbitResetCounts()
{
    if ( !flowbits_hash )
        return;

    for (GHashNode* n = ghash_findfirst(flowbits_hash);
        n != nullptr;
        n = ghash_findnext(flowbits_hash))
    {
        FLOWBITS_OBJECT* fb = (FLOWBITS_OBJECT*)n->data;
        fb->set = 0;
        fb->isset = 0;
    }
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

static bool validateName(char* name)
{
    unsigned i;

    if (!name)
        return false;

    for (i=0; i<strlen(name); i++)
    {
        if (!isalnum(name[i])&&(nullptr == strchr(ALLOWED_SPECIAL_CHARS,name[i])))
            return false;
    }
    return true;
}

static FLOWBITS_OBJECT* getFlowBitItem(char* flowbitName, FLOWBITS_OP* flowbits)
{
    FLOWBITS_OBJECT* flowbits_item;

    if (!validateName(flowbitName))
    {
        ParseAbort("%s: name is limited to any alphanumeric string including %s",
            s_name, ALLOWED_SPECIAL_CHARS);
    }

    flowbits_item = (FLOWBITS_OBJECT*)ghash_find(flowbits_hash, flowbitName);

    if (flowbits_item == nullptr)
    {
        flowbits_item = (FLOWBITS_OBJECT*)snort_calloc(sizeof(FLOWBITS_OBJECT));

        if (sfqueue_count(flowbits_bit_queue) > 0)
        {
            flowbits_item->id = (uint16_t)(uintptr_t)sfqueue_remove(flowbits_bit_queue);
        }
        else
        {
            flowbits_item->id = flowbits_count++;

            if ( !flowbits_count )
            {
                ParseError("The number of flowbit IDs in the current ruleset exceeds "
                    "the maximum number of IDs that are allowed (%u).", flowbits_count-1);
            }
        }

        int hstatus = ghash_add(flowbits_hash, flowbitName, flowbits_item);

        if (hstatus != GHASH_OK)
            ParseError("Could not add flowbits key (%s) to hash.",flowbitName);
    }
    flowbits_item->toggle = flowbits_toggle;
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

static void processFlowbits(
    char* flowbits_names, FLOWBITS_OP* flowbits)
{
    char** toks;
    int num_toks;
    int i;
    char* flowbits_name;

    FLOWBITS_OBJECT* flowbits_item;

    if (!flowbits_names || ((*flowbits_names) == 0))
    {
        return;
    }

    flowbits_name = snort_strdup(flowbits_names);

    if (nullptr != strchr(flowbits_name, '|'))
    {
        if (nullptr != strchr(flowbits_name, '&'))
        {
            ParseError("%s: tag id opcode '|' and '&' are used together.", s_name);
            return;
        }
        toks = mSplit(flowbits_name, "|", 0, &num_toks, 0);
        flowbits->ids = (uint16_t*)snort_calloc(num_toks, sizeof(*(flowbits->ids)));
        flowbits->num_ids = num_toks;
        for (i = 0; i < num_toks; i++)
        {
            flowbits_item = getFlowBitItem(toks[i], flowbits);
            flowbits->ids[i] = flowbits_item->id;
        }
        flowbits->eval = FLOWBITS_OR;
        mSplitFree(&toks, num_toks);
    }
    else if (nullptr != strchr(flowbits_name, '&'))
    {
        toks = mSplit(flowbits_name, "&", 0, &num_toks, 0);
        flowbits->ids = (uint16_t*)snort_calloc(num_toks, sizeof(*(flowbits->ids)));
        flowbits->num_ids = num_toks;
        for (i = 0; i < num_toks; i++)
        {
            flowbits_item = getFlowBitItem(toks[i], flowbits);
            flowbits->ids[i] = flowbits_item->id;
        }
        flowbits->eval = FLOWBITS_AND;
        mSplitFree(&toks, num_toks);
    }
    else if (!strcasecmp(flowbits_name,"all"))
    {
        flowbits->eval = FLOWBITS_ALL;
    }
    else if (!strcasecmp(flowbits_name,"any"))
    {
        flowbits->eval = FLOWBITS_ANY;
    }
    else
    {
        flowbits_item = getFlowBitItem(flowbits_name, flowbits);
        flowbits->ids = (uint16_t*)snort_calloc(sizeof(*(flowbits->ids)));
        flowbits->num_ids = 1;
        flowbits->ids[0] = flowbits_item->id;
    }

    snort_free(flowbits_name);
}

static void validateFlowbitsSyntax(FLOWBITS_OP* flowbits)
{
    switch (flowbits->type)
    {
    case FLOWBITS_SET:
        if ((flowbits->eval == FLOWBITS_AND) && (flowbits->ids))
            break;

        ParseError("%s: operation set uses syntax: flowbits:set,bit[&bit],[group].", s_name);
        return;

    case FLOWBITS_SETX:
        if ((flowbits->eval == FLOWBITS_AND)&&(flowbits->group) && (flowbits->ids) )
            break;

        ParseError("%s: operation setx uses syntax: flowbits:setx,bit[&bit],group.", s_name);
        return;

    case FLOWBITS_UNSET:
        if (((flowbits->eval == FLOWBITS_AND) && (!flowbits->group) && (flowbits->ids))
            ||((flowbits->eval == FLOWBITS_ALL) && (flowbits->group)))
            break;

        ParseError("%s: operation unset uses syntax: flowbits:unset,bit[&bit] OR"
            " flowbits:unset, all, group.", s_name);
        return;

    case FLOWBITS_TOGGLE:
        if (((flowbits->eval == FLOWBITS_AND) && (!flowbits->group) &&(flowbits->ids))
            ||((flowbits->eval == FLOWBITS_ALL) && (flowbits->group)))
            break;

        ParseError("%s: operation toggle uses syntax: flowbits:toggle,bit[&bit] OR"
            " flowbits:toggle,all,group.", s_name);
        return;

    case FLOWBITS_ISSET:
        if ((((flowbits->eval == FLOWBITS_AND) || (flowbits->eval == FLOWBITS_OR)) &&
            (!flowbits->group) && flowbits->ids)
            ||((((flowbits->eval == FLOWBITS_ANY))||(flowbits->eval == FLOWBITS_ALL)) &&
            (flowbits->group)))
            break;

        ParseError("%s: operation isset uses syntax: flowbits:isset,bit[&bit] OR "
            "flowbits:isset,bit[|bit] OR flowbits:isset,all,group OR flowbits:isset,any,group.",
            s_name);
        return;

    case FLOWBITS_ISNOTSET:
        if ((((flowbits->eval == FLOWBITS_AND) || (flowbits->eval == FLOWBITS_OR)) &&
            (!flowbits->group) && flowbits->ids)
            ||((((flowbits->eval == FLOWBITS_ANY))||(flowbits->eval == FLOWBITS_ALL)) &&
            (flowbits->group)))
            break;

        ParseError("%s: operation isnotset uses syntax: flowbits:isnotset,bit[&bit] OR "
            "flowbits:isnotset,bit[|bit] OR flowbits:isnotset,all,group OR "
            "flowbits:isnotset,any,group.", s_name);
        return;

    case FLOWBITS_RESET:
        if (flowbits->ids == nullptr)
            break;
        ParseError(
            "%s: operation unset uses syntax: flowbits:reset OR flowbits:reset, group.", s_name);
        return;

    case FLOWBITS_NOALERT:
        if ((flowbits->ids == nullptr) && (flowbits->group == nullptr))
            break;
        ParseError("%s: operation noalert uses syntax: flowbits:noalert.", s_name);
        return;

    default:
        ParseError("%s: unknown opcode.", s_name);
        return;
    }
}

static FLOWBITS_GRP* getFlowBitGroup(char* groupName)
{
    FLOWBITS_GRP* flowbits_grp = nullptr;

    if (!groupName)
        return nullptr;

    if (!validateName(groupName))
    {
        ParseAbort(
            "%s: flowbits group name is limited to any alphanumeric string including %s",
            s_name, ALLOWED_SPECIAL_CHARS);
    }

    flowbits_grp = (FLOWBITS_GRP*)ghash_find(flowbits_grp_hash, groupName);

    if ( !flowbits_grp )
    {
        // new group defined, add (bitop set later once we know size)
        flowbits_grp = (FLOWBITS_GRP*)snort_calloc(sizeof(*flowbits_grp));
        int hstatus = ghash_add(flowbits_grp_hash, groupName, flowbits_grp);

        if (hstatus != GHASH_OK)
            ParseAbort("Could not add flowbits group (%s) to hash.\n",groupName);

        flowbits_grp_count++;
        flowbits_grp->group_id = flowbits_grp_count;
        flowbits_grp->name = snort_strdup(groupName);
    }

    return flowbits_grp;
}

static void processFlowBitsWithGroup(char* flowbitsName, char* groupName, FLOWBITS_OP* flowbits)
{
    FLOWBITS_GRP* flowbits_grp;

    flowbits_grp = getFlowBitGroup(groupName);
    processFlowbits(flowbitsName, flowbits);

    if (groupName && !(flowbits->group))
    {
        flowbits->group = snort_strdup(groupName);
        flowbits->group_id = flowbits_grp->group_id;
    }
    validateFlowbitsSyntax(flowbits);

    if ( flowbits->group )
        op_list.push_front(flowbits);
}

static FLOWBITS_OP* flowbits_parse(const char* data)
{
    char** toks;
    int num_toks;
    char* typeName = nullptr;
    char* groupName = nullptr;
    char* flowbitsName = nullptr;
    FLOWBITS_GRP* flowbits_grp;

    FLOWBITS_OP* flowbits = (FLOWBITS_OP*)snort_calloc(sizeof(*flowbits));

    toks = mSplit(data, ",", 0, &num_toks, 0);

    if (num_toks < 1)
    {
        ParseAbort("%s: must specify operation.", s_name);
    }
    else if (num_toks > 3)
    {
        ParseAbort("%s: too many arguments.", s_name);
    }

    typeName = toks[0];

    if (!strcasecmp("set",typeName))
    {
        flowbits->type = FLOWBITS_SET;
    }
    else if (!strcasecmp("setx",typeName))
    {
        flowbits->type = FLOWBITS_SETX;
    }
    else if (!strcasecmp("unset",typeName))
    {
        flowbits->type = FLOWBITS_UNSET;
    }
    else if (!strcasecmp("toggle",typeName))
    {
        flowbits->type = FLOWBITS_TOGGLE;
    }
    else if (!strcasecmp("isset",typeName))
    {
        flowbits->type = FLOWBITS_ISSET;
    }
    else if (!strcasecmp("isnotset",typeName))
    {
        flowbits->type = FLOWBITS_ISNOTSET;
    }
    else if (!strcasecmp("noalert", typeName))
    {
        if (num_toks > 1)
        {
            ParseAbort("%s: do not specify a tag id for the keyword 'noalert'.", s_name);
        }

        flowbits->type = FLOWBITS_NOALERT;
        flowbits->ids = nullptr;
        flowbits->num_ids = 0;
        flowbits->name = snort_strdup(typeName);

        mSplitFree(&toks, num_toks);
        return flowbits;
    }
    else if (!strcasecmp("reset",typeName))
    {
        if (num_toks > 2)
        {
            ParseAbort("%s: too many arguments for the keyword 'reset'.", s_name);
        }

        if (num_toks == 2)
        {
            /*Save the group name*/
            groupName = snort_strdup(toks[1]);
            flowbits_grp = getFlowBitGroup(groupName);
            flowbits->group = groupName;
            flowbits->group_id = flowbits_grp->group_id;
        }
        flowbits->type = FLOWBITS_RESET;
        flowbits->ids = nullptr;
        flowbits->num_ids = 0;
        flowbits->name = snort_strdup(typeName);
        mSplitFree(&toks, num_toks);
        return flowbits;
    }
    else
    {
        ParseAbort("%s: invalid token %s.", s_name, typeName);
    }

    flowbits->name = snort_strdup(typeName);
    /*
     **  Let's parse the flowbits name
     */
    if ( num_toks < 2 )
    {
        ParseAbort("flowbit: flowbits tag id must be provided.");
    }

    flowbitsName = toks[1];

    if (num_toks == 3)
    {
        groupName = toks[2];
    }
    processFlowBitsWithGroup(flowbitsName, groupName, flowbits);

    mSplitFree(&toks, num_toks);
    return flowbits;
}

static void update_group(FLOWBITS_GRP* flowbits_grp, int id)
{
    flowbits_grp->count++;

    if ( flowbits_grp->max_id < id )
        flowbits_grp->max_id = id;

    flowbits_grp->GrpBitOp->set(id);
}

static void init_groups()
{
    if ( !flowbits_hash or !flowbits_grp_hash )
        return;

    for ( GHashNode* n = ghash_findfirst(flowbits_grp_hash);
        n != nullptr;
        n= ghash_findnext(flowbits_grp_hash) )
    {
        FLOWBITS_GRP* fbg = (FLOWBITS_GRP*)n->data;
        fbg->GrpBitOp = new BitOp(flowbits_count);
        fbg->GrpBitOp->reset();
    }

    while ( !op_list.empty() )
    {
        const FLOWBITS_OP* fbop = op_list.front();
        FLOWBITS_GRP* fbg = (FLOWBITS_GRP*)ghash_find(flowbits_grp_hash, fbop->group);
        assert(fbg);

        for ( int i = 0; i < fbop->num_ids; ++i )
            update_group(fbg, fbop->ids[i]);

        op_list.pop_front();
    }
}

static void FlowBitsVerify()
{
    GHashNode* n;
    unsigned num_flowbits = 0;
    unsigned unchecked = 0, unset = 0;

    if (flowbits_hash == nullptr)
        return;

    for (n = ghash_findfirst(flowbits_hash);
        n != nullptr;
        n= ghash_findnext(flowbits_hash))
    {
        FLOWBITS_OBJECT* fb = (FLOWBITS_OBJECT*)n->data;

        if (fb->toggle != flowbits_toggle)
        {
            sfqueue_add(flowbits_bit_queue, (NODE_DATA)(uintptr_t)fb->id);
            ghash_remove(flowbits_hash, n->key);
            continue;
        }

        if ((fb->set > 0) && (fb->isset == 0))
        {
            ParseWarning(WARN_FLOWBITS, "%s key '%s' is set but not checked.",
                s_name, (const char*)n->key);
            unchecked++;
        }
        else if ((fb->isset > 0) && (fb->set == 0))
        {
            ParseWarning(WARN_FLOWBITS, "%s key '%s' is checked but not ever set.",
                s_name, (const char*)n->key);
            unset++;
        }
        else if ((fb->set == 0) && (fb->isset == 0))
        {
            continue; /* don't count this bit as used */
        }

        num_flowbits++;
    }
    assert(num_flowbits == flowbits_count);

    flowbits_toggle ^= 1;

    if ( !num_flowbits )
        return;

    LogLabel(s_name);
    LogCount("defined", num_flowbits);
    LogCount("not checked", unchecked);
    LogCount("not set", unset);
}

static void FlowItemFree(void* d)
{
    FLOWBITS_OBJECT* data = (FLOWBITS_OBJECT*)d;
    snort_free(data);
}

static void FlowBitsGrpFree(void* d)
{
    FLOWBITS_GRP* data = (FLOWBITS_GRP*)d;
    if(data->GrpBitOp)
        delete data->GrpBitOp;
    if (data->name)
        snort_free(data->name);
    snort_free(data);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void flowbits_ginit(SnortConfig*)
{
    flowbits_hash = ghash_new(10000, 0, 0, FlowItemFree);

    if ( !flowbits_hash )
        FatalError("Could not create flowbits hash.\n");

    // this is used during parse time and runtime so do NOT
    // enable splay mode (which is NOT useful here anyway)
    flowbits_grp_hash = ghash_new(10000, 0, 0, FlowBitsGrpFree);

    if ( !flowbits_grp_hash )
        FatalError("could not create flowbits group hash.\n");

    flowbits_bit_queue = sfqueue_new();

    if ( !flowbits_bit_queue )
        FatalError("could not create flowbits bit queue.\n");
}

static void flowbits_gterm(SnortConfig*)
{
    if ( flowbits_hash )
    {
        ghash_delete(flowbits_hash);
        flowbits_hash = nullptr;
    }

    if ( flowbits_grp_hash )
    {
        ghash_delete(flowbits_grp_hash);
        flowbits_grp_hash = nullptr;
    }

    if ( flowbits_bit_queue )
    {
        sfqueue_free_all(flowbits_bit_queue, nullptr);
        flowbits_bit_queue = nullptr;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~command", Parameter::PT_STRING, nullptr, nullptr,
      "set|reset|isset|etc." },  // FIXIT-L replace this legacy flowbits parsing with PT_SELECT

    { "~arg1", Parameter::PT_STRING, nullptr, nullptr,
      "bits or group" },

    { "~arg2", Parameter::PT_STRING, nullptr, nullptr,
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

    ProfileStats* get_profile() const override
    { return &flowBitsPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    string args;
};

bool FlowbitsModule::begin(const char*, int, SnortConfig*)
{
    args.clear();
    return true;
}

bool FlowbitsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~command") )
        args = v.get_string();

    else if ( v.is("~arg1") || v.is("~arg2") )
    {
        args += ", ";
        args += v.get_string();
    }
    else
        return false;

    return true;
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
    delete m;
}

static IpsOption* flowbits_ctor(Module* p, OptTreeNode*)
{
    FlowbitsModule* m = (FlowbitsModule*)p;
    FLOWBITS_OP* fbop = flowbits_parse(m->args.c_str());
    return new FlowBitsOption(fbop);
}

static void flowbits_dtor(IpsOption* p)
{
    delete p;
}

// FIXIT-M updating statics during reload is bad, mkay?
static void flowbits_verify(SnortConfig*)
{
    init_groups();
    FlowBitsVerify();
}

#if 0
// FIXIT-M if add_detection_option() finds a dup, then
// we can leak the original group name if same as current
// also, why use new group name instead of original?
char* group_name =  ((FLOWBITS_OP*)idx_dup)->group;

if (flowbits->group)
{
    if (group_name && strcmp(group_name, flowbits->group))
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
    flowbits_ginit,
    flowbits_gterm,
    nullptr,
    nullptr,
    flowbits_ctor,
    flowbits_dtor,
    flowbits_verify
};

const BaseApi* ips_flowbits = &flowbits_api.base;

