//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2008-2013 Sourcefire, Inc.
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

#ifndef TREENODES_H
#define TREENODES_H

// rule header (RTN) and body (OTN) nodes

#include "actions/actions.h"
#include "detection/signature.h"
#include "detection/rule_option_types.h"
#include "main/snort_types.h"
#include "time/clock_defs.h"

namespace snort
{
class IpsOption;
struct Packet;
}
struct RuleTreeNode;
struct PortObject;
struct OutputSet;
struct TagData;
struct sfip_var_t;

/* same as the rule header FP list */
struct OptFpList
{
    snort::IpsOption* ips_opt;

    int (* OptTestFunc)(void* option_data, class Cursor&, snort::Packet*);

    OptFpList* next;

    unsigned char isRelative;
    option_type_t type;
};

struct OtnState
{
    // profiling
    // FIXIT-L factor the profiling stuff out
    hr_duration elapsed = 0_ticks;
    hr_duration elapsed_match = 0_ticks;
    hr_duration elapsed_no_match = 0_ticks;

    uint64_t checks = 0;
    uint64_t matches = 0;
    uint8_t noalerts = 0;
    uint64_t alerts = 0;

    uint64_t latency_timeouts = 0;
    uint64_t latency_suspends = 0;

    operator bool() const
    { return elapsed > 0_ticks || checks > 0; }
};

// one of these for each rule
// represents body part of rule
struct OptTreeNode
{
    /* plugin/detection functions go here */
    OptFpList* opt_func;
    OutputSet* outputFuncs; /* per sid enabled output functions */
    snort::IpsOption* agent;

    /* metadata about signature */
    SigInfo sigInfo;
    char* soid;

    struct THD_NODE* detection_filter; /* if present, evaluated last, after header checks */
    TagData* tag;

    // ptr to list of RTNs (head part); indexed by policyId
    RuleTreeNode** proto_nodes;

    OtnState* state;

    int chain_node_number;
    int evalIndex;       /* where this rule sits in the evaluation sets */

    // Added for integrity checks during rule parsing.
    SnortProtocolId snort_protocol_id;

    unsigned ruleIndex; // unique index

    bool warned_fp;
    bool enabled;

    uint32_t num_detection_opts;
    uint32_t plugins;

    /**number of proto_nodes. */
    unsigned short proto_node_num;

    uint16_t longestPatternLen;

    uint8_t stateless;  /* this rule can fire regardless of session state */
    uint8_t established; /* this rule can only fire if it is established */
    uint8_t unestablished;

    char generated;
};

/* function pointer list for rule head nodes */
// FIXIT-L use bit mask to determine what header checks to do
// cheaper than traversing a list and uses much less memory
struct RuleFpList
{
    /* context data for this test */
    void* context;

    /* rule check function pointer */
    int (* RuleHeadFunc)(snort::Packet*, RuleTreeNode*, RuleFpList*, int);

    /* pointer to the next rule function node */
    RuleFpList* next;
};

// one of these per rule per policy
// represents head part of rule
struct RuleTreeNode
{
    RuleFpList* rule_func; /* match functions.. (Bidirectional etc.. ) */

    sfip_var_t* sip;
    sfip_var_t* dip;

    PortObject* src_portobject;
    PortObject* dst_portobject;

    struct ListHead* listhead;

    SnortProtocolId snort_protocol_id;

    uint32_t flags;     /* control flags */

    snort::Actions::Type type;

    // reference count from otn.
    // Multiple OTNs can reference this RTN with the same policy.
    unsigned int otnRefCount;
};

typedef int (* RuleOptEvalFunc)(void*, Cursor&, snort::Packet*);
OptFpList* AddOptFuncToList(RuleOptEvalFunc, OptTreeNode*);

void* get_rule_type_data(OptTreeNode*, const char* name);

SO_PUBLIC bool otn_has_plugin(OptTreeNode* otn, const char* name);

inline bool otn_has_plugin(OptTreeNode* otn, int id)
{ return (otn->plugins & (0x1 << id)) != 0; }

inline void otn_set_plugin(OptTreeNode* otn, int id)
{ otn->plugins |= (0x1 << id); }

bool otn_set_agent(OptTreeNode*, snort::IpsOption*);

void otn_trigger_actions(const OptTreeNode*, snort::Packet*);

#endif

