//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <string>

#include "detection/signature.h"
#include "detection/rule_option_types.h"
#include "framework/ips_action.h"
#include "framework/pdu_section.h"
#include "main/policy.h"
#include "main/snort_types.h"
#include "ports/port_group.h"
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

    bool is_active() const
    { return elapsed > CLOCK_ZERO || checks > 0; }
};

/* function pointer list for rule head nodes */
// FIXIT-L use bit mask to determine what header checks to do
// cheaper than traversing a list and uses much less memory
struct RuleFpList
{
    /* context data for this test */
    void* context = nullptr;

    /* rule check function pointer */
    int (* RuleHeadFunc)(snort::Packet*, RuleTreeNode*, RuleFpList*, int) = nullptr;

    /* pointer to the next rule function node */
    RuleFpList* next = nullptr;
};

struct RuleHeader
{
    RuleHeader(const char* s) : action(s) { }

    std::string action;
    std::string proto;
    std::string src_nets;
    std::string src_ports;
    std::string dir;
    std::string dst_nets;
    std::string dst_ports;
};

// one of these per rule per policy
// represents head part of rule
struct RuleTreeNode
{
    using Flag = uint8_t;
    static constexpr Flag ENABLED       = 0x01;
    static constexpr Flag ANY_SRC_PORT  = 0x02;
    static constexpr Flag ANY_DST_PORT  = 0x04;
    static constexpr Flag ANY_FLAGS     = 0x08;
    static constexpr Flag BIDIRECTIONAL = 0x10;
    static constexpr Flag ANY_SRC_IP    = 0x20;
    static constexpr Flag ANY_DST_IP    = 0x40;
    static constexpr Flag USER_MODE     = 0x80;

    RuleFpList* rule_func = nullptr; /* match functions.. (Bidirectional etc.. ) */
    RuleHeader* header = nullptr;

    sfip_var_t* sip = nullptr;
    sfip_var_t* dip = nullptr;

    PortObject* src_portobject = nullptr;
    PortObject* dst_portobject = nullptr;

    struct ListHead* listhead = nullptr;

    SnortProtocolId snort_protocol_id = 0;

    // reference count from otn.
    // Multiple OTNs can reference this RTN with the same policy.
    unsigned int otnRefCount = 0; // FIXIT-L shared_ptr?

    snort::IpsAction::Type action = 0;

    uint8_t flags = 0;

    void set_enabled()
    { flags |= ENABLED; }

    void clear_enabled()
    { flags &= (~ENABLED); }

    bool enabled() const
    { return (flags & ENABLED) != 0; }

    bool user_mode() const
    { return (flags & USER_MODE) != 0; }

    bool any_src_port() const
    { return (flags & ANY_SRC_PORT) != 0; }

    bool any_dst_port() const
    { return (flags & ANY_DST_PORT) != 0; }

    bool any_any_port() const
    { return any_src_port() and any_dst_port(); }
};

// one of these for each rule
// represents body part of rule
struct OptTreeNode
{
    ~OptTreeNode();

    using Flag = uint8_t;
    static constexpr Flag WARNED_FP  = 0x01;
    static constexpr Flag STATELESS  = 0x02;
    static constexpr Flag RULE_STATE = 0x04;
    static constexpr Flag META_MATCH = 0x08;
    static constexpr Flag TO_CLIENT  = 0x10;
    static constexpr Flag TO_SERVER  = 0x20;
    static constexpr Flag BIT_CHECK  = 0x40;
    static constexpr Flag SVC_ONLY   = 0x80;

    /* metadata about signature */
    SigInfo sigInfo;
    char* soid = nullptr;

    /* plugin/detection functions go here */
    OptFpList* opt_func = nullptr;
    OutputSet* outputFuncs = nullptr; /* per sid enabled output functions */
    snort::IpsOption* agent = nullptr;
    const char** buffer_setters = nullptr;

    OptFpList* normal_fp_only = nullptr;
    OptFpList* offload_fp_only = nullptr;

    struct THD_NODE* detection_filter = nullptr; /* if present, evaluated last, after header checks */
    TagData* tag = nullptr;

    // ptr to list of RTNs (head part); indexed by policyId
    RuleTreeNode** proto_nodes = nullptr;
    OtnState* state = nullptr;

    unsigned evalIndex = 0;       /* where this rule sits in the evaluation sets */
    unsigned ruleIndex = 0; // unique index
    uint32_t num_detection_opts = 0;
    SnortProtocolId snort_protocol_id = 0;    // Added for integrity checks during rule parsing.
    unsigned short proto_node_num = 0;
    uint16_t longestPatternLen = 0;
    IpsPolicy::Enable enable = IpsPolicy::Enable::DISABLED;
    Flag flags = 0;

    enum SectionDir { SECT_TO_SRV = 0, SECT_TO_CLIENT, SECT_DIR__MAX };
    snort::section_flags sections[SECT_DIR__MAX] = { section_to_flag(snort::PS_NONE),
        section_to_flag(snort::PS_NONE) };

    void set_warned_fp()
    { flags |= WARNED_FP; }

    bool warned_fp() const
    { return (flags & WARNED_FP) != 0; }

    void set_stateless()
    { flags |= STATELESS; }

    bool stateless() const
    { return (flags & STATELESS) != 0; }

    void set_enabled(IpsPolicy::Enable e)
    { enable = e; flags |= RULE_STATE; }

    bool is_rule_state_stub() const
    { return (flags & RULE_STATE) != 0; }

    bool enabled_somewhere() const
    {
        for ( unsigned i = 0; i < proto_node_num; i++ )
            if ( proto_nodes[i] and proto_nodes[i]->enabled() )
                return true;

        return false;
    }

    void set_metadata_match()
    { flags |= META_MATCH; }

    bool metadata_matched() const
    { return (flags & META_MATCH) != 0; }

    void set_to_client()
    { flags |= TO_CLIENT; }

    bool to_client() const
    { return (flags & TO_CLIENT) != 0; }

    void set_to_server()
    { flags |= TO_SERVER; }

    bool to_server() const
    { return (flags & TO_SERVER) != 0; }

    void set_flowbits_check()
    { flags |= BIT_CHECK; }

    bool checks_flowbits() const
    { return (flags & BIT_CHECK) != 0; }

    void set_service_only()
    { flags |= SVC_ONLY; }

    bool service_only() const
    { return (flags & SVC_ONLY) != 0; }

    void update_fp(snort::IpsOption*);

    bool to_client_err() const
    { return sections[SECT_TO_CLIENT] == section_to_flag(snort::PS_ERROR); }

    bool to_server_err() const
    { return sections[SECT_TO_SRV] == section_to_flag(snort::PS_ERROR); }
};

typedef int (* RuleOptEvalFunc)(void*, Cursor&, snort::Packet*);
OptFpList* AddOptFuncToList(RuleOptEvalFunc, OptTreeNode*);

namespace snort
{
SO_PUBLIC bool otn_has_plugin(OptTreeNode* otn, const char* name);
}

bool otn_set_agent(OptTreeNode*, snort::IpsOption*);

void otn_trigger_actions(const OptTreeNode*, snort::Packet*);

#endif

