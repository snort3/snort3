//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SNORT_CONFIG_H
#define SNORT_CONFIG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <vector>
#include <map>
#include <sys/stat.h>
#include "detection/rules.h"
#include "sfip/sfip_t.h"
#include "main/policy.h"
#include "utils/util.h"
#include "protocols/packet.h"
#include "main/thread.h"
#include "framework/bits.h"
#include "file_api/libs/file_config.h"

#define DEFAULT_LOG_DIR "."

#ifdef PERF_PROFILING
#include "time/profiler.h"
#endif

struct PORT_RULE_MAP;
struct SFXHASH;
struct srmm_table_t;
struct sopg_table_t;

// defined in sfghash.h  forward declared here
struct sf_list;
typedef sf_list SF_LIST;

#if 0
FIXIT-L
typedef enum _PathType
{
    PATH_TYPE__FILE,
    PATH_TYPE__DIRECTORY
} PathType;

#endif

// SnortState members are updated during runtime
// an array in SnortConfig is used instead of thread_locals because these
// must get changed on reload
struct SnortState
{
    int* pcre_ovector;
};

struct SnortConfig
{
    //------------------------------------------------------
    // alert module stuff
    int default_rule_state;

    uint16_t flowbit_size;
    sfip_t homenet;

    //------------------------------------------------------
    // output module stuff
    uint32_t output_flags;
    uint32_t logging_flags;
    uint32_t warning_flags;

    uint8_t log_ipv6_extra;
    uint16_t event_trace_max;
    long int tagged_packet_limit;

    char* event_trace_file;
    char* log_dir;           /* -l or config log_dir */

    //------------------------------------------------------
    // daq stuff
    char* daq_type;          /* --daq or config daq */
    char* daq_mode;          /* --daq-mode or config daq_mode */
    void* daq_vars;          /* --daq-var or config daq_var */
    void* daq_dirs;          /* --daq-dir or config daq_dir */

    //------------------------------------------------------
    // detection module stuff
    long int pcre_match_limit;
    long int pcre_match_limit_recursion;
    int pcre_ovector_size;  // computed from rules

    int asn1_mem;
    int run_flags;

    //------------------------------------------------------
    // process stuff
    int user_id;
    int group_id;

    int dirty_pig;

    char* chroot_dir;        /* -t or config chroot */

    char* plugin_path;
    char* script_path;

    mode_t file_mask;

    //------------------------------------------------------
    // decode module stuff
    uint8_t mpls_payload_type;
    long int mpls_stack_depth;

    uint8_t enable_teredo;
    uint8_t enable_esp;
    PortList* gtp_ports;

    uint8_t num_layers;
    uint8_t max_ip6_extensions;
    uint8_t max_ip_layers;
    int pkt_snaplen;

    //------------------------------------------------------
    // active stuff
    uint8_t respond_attempts;
    uint8_t max_responses;
    uint8_t min_interval;
    char* respond_device;
    uint8_t* eth_dst;

    char* output;

    //------------------------------------------------------
    // attribute tables stuff
    uint32_t max_attribute_hosts;
    uint32_t max_attribute_services_per_host;
    uint32_t max_metadata_services;

    //------------------------------------------------------
    // packet module stuff
    uint8_t vlan_agnostic;
    uint8_t addressspace_agnostic;

    uint64_t pkt_cnt;           /* -n */
    uint64_t pkt_skip;

    char* bpf_file;          /* -F or config bpf_file */

    //------------------------------------------------------
    // various modules
    struct FastPatternConfig* fast_pattern_config;
    struct EventQueueConfig* event_queue_config;

    FileConfig* file_config;

    /* XXX XXX policy specific? */
    struct ThresholdConfig* threshold_config;
    struct RateFilterConfig* rate_filter_config;

    //------------------------------------------------------
    // FIXIT-L command line only stuff, add to conf / module

    uint32_t event_log_id;      /* -G */
    sfip_t obfuscation_net;  // -B
    char* bpf_filter;        // --bpf

    //------------------------------------------------------
    // FIXIT-L non-module stuff - separate config from derived state?
    char* run_prefix;
    bool id_subdir;
    bool id_zero;

    bool stdin_rules;

    char pid_filename[STD_BUF];
    char* orig_log_dir;      /* set in case of chroot */

    int thiszone;

    struct RuleState* rule_state_list;
    struct ClassType* classifications;
    struct ReferenceSystemNode* references;
    struct SFGHASH* otn_map;

    struct DetectionFilterConfig* detection_filter_config;

    SF_LIST** ip_proto_only_lists;
    uint8_t ip_proto_array[NUM_IP_PROTOS];

    int num_rule_types;
    struct RuleListNode* rule_lists;
    int evalOrder[RULE_TYPE__MAX + 1];

    ListHead Alert;
    ListHead Log;
    ListHead Pass;
    ListHead Drop;
    ListHead SDrop;

    struct FrameworkConfig* framework_config;

    /* master port list table */
    struct RulePortTables* port_tables;

    /* The port-rule-maps map the src-dst ports to rules for
     * udp and tcp, for Ip we map the dst port as the protocol,
     * and for Icmp we map the dst port to the Icmp type. This
     * allows us to use the decode packet information to in O(1)
     * select a group of rules to apply to the packet.  These
     * rules may or may not have content.  We process the content
     * 1st and then the no content rules for udp/tcp and icmp, and
     * then we process the ip rules. */
    PORT_RULE_MAP* prmIpRTNX;
    PORT_RULE_MAP* prmTcpRTNX;
    PORT_RULE_MAP* prmUdpRTNX;
    PORT_RULE_MAP* prmIcmpRTNX;

    srmm_table_t* srmmTable;   /* srvc rule map master table */
    srmm_table_t* spgmmTable;  /* srvc port_group map master table */
    sopg_table_t* sopgTable;   /* service-oridnal to port_group table */

    SFXHASH* detection_option_hash_table;
    SFXHASH* detection_option_tree_hash_table;

    PolicyMap* policy_map;

    uint8_t tunnel_mask;

    uint32_t so_rule_memcap;
    char* output_dir;

    struct VarNode* var_list;

    //------------------------------------------------------
    // deliberately not conditional
    // to avoid plugin compatibility issues
    struct ProfileConfig* profile_rules;
    struct ProfileConfig* profile_preprocs;

    struct ppm_cfg_t* ppm_cfg;
    struct _IntelPmHandles* ipm_handles;

    unsigned remote_control;
    //------------------------------------------------------

    SnortState* state;
    unsigned num_slots;

    std::map<const std::string, int>* source_affinity;
    std::vector<int>* thread_affinity;

    InspectionPolicy* get_inspection_policy()
    { return policy_map->inspection_policy[0]; }

    IpsPolicy* get_ips_policy()
    { return policy_map->ips_policy[0]; }

    NetworkPolicy* get_network_policy()
    { return policy_map->network_policy[0]; }

    inline uint8_t get_num_layers() const
    { return num_layers; }

    // curr_layer is the zero based ip6 options
    inline bool hit_ip6_maxopts(uint8_t curr_opt) const
    { return max_ip6_extensions && (curr_opt >= max_ip6_extensions); }

    // curr_ip is the zero based ip layer
    inline bool hit_ip_maxlayers(uint8_t curr_ip) const
    { return max_ip_layers && (curr_ip >= max_ip_layers); }
};

SnortConfig* SnortConfNew(void);
void SnortConfSetup(SnortConfig*);
void SnortConfFree(SnortConfig*);
SnortConfig* MergeSnortConfs(SnortConfig* cmd_line, SnortConfig* config_file);
int VerifyReload(SnortConfig*);

#endif

