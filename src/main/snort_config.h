/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef SNORT_CONFIG_H
#define SNORT_CONFIG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "detection/fpcreate.h"
#include "detection/pcrm.h"
#include "events/event_queue.h"
#include "events/sfeventq.h"
#include "filters/sfthreshold.h"
#include "filters/sfrf.h"
#include "filters/detection_filter.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sfip_t.h"
#include "detection/rules.h"
#include "detection/signature.h"
#include "time/ppm.h"
#include "time/profiler.h"
#include "utils/sflsq.h"
#include "hash/sfxhash.h"
#include "utils/sfportobject.h"
#include "hash/sfghash.h"
#include "main/policy.h"

#define MAX_PIDFILE_SUFFIX 11 /* uniqueness extension to PID file, see '-R' */

#define DEFAULT_LOG_DIR "."

#ifdef INTEL_SOFT_CPM
struct _IntelPmHandles;
#endif
struct FrameworkConfig;

typedef enum _PathType
{
    PATH_TYPE__FILE,
    PATH_TYPE__DIRECTORY

} PathType;

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
    char *alert_file;
    int default_rule_state;

    uint16_t flowbit_size;
    sfip_t homenet;

    //------------------------------------------------------
    // output module stuff
    int output_flags;
    int logging_flags;

    uint8_t log_ipv6_extra;
    uint16_t event_trace_max;
    long int tagged_packet_limit;

    char* event_trace_file;
    char *log_dir;           /* -l or config log_dir */

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
    // profling module stuff
#ifdef PERF_PROFILING
    ProfileConfig profile_rules;
    ProfileConfig profile_preprocs;
#endif

    //------------------------------------------------------
    // process stuff
    int user_id;
    int group_id;

    int dirty_pig;

    char *chroot_dir;        /* -t or config chroot */

    char* plugin_path;
    char* script_path;

    mode_t file_mask;

    //------------------------------------------------------
    // decode module stuff
    uint8_t mpls_payload_type;
    long int mpls_stack_depth;

    uint8_t enable_teredo;
    uint8_t enable_gtp;
    char *gtp_ports;
    uint8_t enable_esp;

    int pkt_snaplen;

    //------------------------------------------------------
    // active stuff
    uint8_t respond_attempts;
    uint8_t max_responses;
    uint8_t min_interval;
    char* respond_device;
    uint8_t *eth_dst;

    char* react_page;
    const char* output;

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

    char *bpf_file;          /* -F or config bpf_file */

    //------------------------------------------------------
    // various modules
    FastPatternConfig *fast_pattern_config;
    EventQueueConfig *event_queue_config;
    void *file_config;

    /* XXX XXX policy specific? */
    ThresholdConfig *threshold_config;
    RateFilterConfig *rate_filter_config;

#ifdef PPM_MGR
    ppm_cfg_t ppm_cfg;
#endif

    //------------------------------------------------------
    // FIXIT command line only stuff, add to conf / module

    uint32_t event_log_id;      /* -G */
    sfip_t obfuscation_net;  // -B
    char *bpf_filter;        // --bpf

    //------------------------------------------------------
    // FIXIT non-module stuff - separate config from derived state?

    char pid_filename[STD_BUF];
    char *orig_log_dir;      /* set in case of chroot */

    int thiszone;

    RuleState *rule_state_list;
    ClassType *classifications;
    ReferenceSystemNode *references;
    SFGHASH *otn_map;

    DetectionFilterConfig *detection_filter_config;

    SF_LIST **ip_proto_only_lists;
    uint8_t ip_proto_array[NUM_IP_PROTOS];

    int num_rule_types;
    RuleListNode *rule_lists;
    int evalOrder[RULE_TYPE__MAX + 1];

    ListHead Alert;
    ListHead Log;
    ListHead Pass;
    ListHead Drop;
    ListHead SDrop;
    ListHead Reject;

    struct FrameworkConfig* framework_config;

    /* master port list table */
    rule_port_tables_t *port_tables;

    /* The port-rule-maps map the src-dst ports to rules for
     * udp and tcp, for Ip we map the dst port as the protocol,
     * and for Icmp we map the dst port to the Icmp type. This
     * allows us to use the decode packet information to in O(1)
     * select a group of rules to apply to the packet.  These
     * rules may have uricontent, content, or they may be no content
     * rules, or any combination. We process the uricontent 1st,
     * then the content, and then the no content rules for udp/tcp
     * and icmp, than we process the ip rules. */
    PORT_RULE_MAP *prmIpRTNX;
    PORT_RULE_MAP *prmTcpRTNX;
    PORT_RULE_MAP *prmUdpRTNX;
    PORT_RULE_MAP *prmIcmpRTNX;

    srmm_table_t *srmmTable;   /* srvc rule map master table */
    srmm_table_t *spgmmTable;  /* srvc port_group map master table */
    sopg_table_t *sopgTable;   /* service-oridnal to port_group table */

    SFXHASH *detection_option_hash_table;
    SFXHASH *detection_option_tree_hash_table;

    PolicyMap* policy_map;

    char *base_version;

    uint8_t tunnel_mask;

    uint32_t so_rule_memcap;
    char *output_dir;

    struct VarNode* var_list;

    int max_threads;
    unsigned remote_control;

    SnortState* state;

#ifdef UNIT_TEST
    bool unit_test;
#endif

    InspectionPolicy* get_inspection_policy()
    { return policy_map->get_inspection_policy(); };

    IpsPolicy* get_ips_policy()
    { return policy_map->get_ips_policy(); };

    NetworkPolicy* get_network_policy()
    { return policy_map->get_network_policy(); };
};

SnortConfig* SnortConfNew(void);
void SnortConfFree(SnortConfig*);
SnortConfig * MergeSnortConfs(SnortConfig* cmd_line, SnortConfig* config_file);
int VerifyReload(SnortConfig*);

#endif

