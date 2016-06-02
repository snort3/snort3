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

#ifndef SNORT_CONFIG_H
#define SNORT_CONFIG_H

// SnortConfig encapsulates all data loaded from the config files.
// FIXIT-L privatize most of this stuff.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <map>
#include <string>
#include <vector>
#include <sys/stat.h>

#include "sfip/sfip_t.h"
#include "main/policy.h"
#include "utils/util.h"
#include "protocols/packet.h"
#include "framework/bits.h"
#include "events/event_queue.h"
#include "file_api/file_config.h"

#define DEFAULT_LOG_DIR "."

enum RunFlag
{
    RUN_FLAG__READ                = 0x00000001,     /* -r, --pcap-list, --pcap-file, --pcap-dir */
    RUN_FLAG__DAEMON              = 0x00000002,     /* -D */
    RUN_FLAG__NO_PROMISCUOUS      = 0x00000004,     /* -p */
    /* UNUSED                       0x00000008 */

    RUN_FLAG__INLINE              = 0x00000010,     /* -Q */
    RUN_FLAG__STATIC_HASH         = 0x00000020,     /* -H */
    RUN_FLAG__CREATE_PID_FILE     = 0x00000040,     /* --pid-path and --create-pidfile */
    RUN_FLAG__NO_LOCK_PID_FILE    = 0x00000080,     /* --nolock-pidfile */

    RUN_FLAG__TREAT_DROP_AS_ALERT = 0x00000100,     /* --treat-drop-as-alert */
    RUN_FLAG__ALERT_BEFORE_PASS   = 0x00000200,     /* --alert-before-pass */
    RUN_FLAG__CONF_ERROR_OUT      = 0x00000400,     /* -x and --conf-error-out */
    RUN_FLAG__MPLS_MULTICAST      = 0x00000800,     /* --enable_mpls_multicast */

    RUN_FLAG__MPLS_OVERLAPPING_IP = 0x00001000,     /* --enable_mpls_overlapping_ip */
    RUN_FLAG__PROCESS_ALL_EVENTS  = 0x00002000,
    RUN_FLAG__INLINE_TEST         = 0x00004000,     /* --enable-inline-test*/
    RUN_FLAG__PCAP_SHOW           = 0x00008000,

    /* UNUSED                       0x00010000 */
    RUN_FLAG__PAUSE               = 0x00020000,     // --pause
    RUN_FLAG__NO_PCRE             = 0x00040000,
    /* If stream is configured, the STATEFUL flag is set.  This is
     * somewhat misnamed and is used to assure a session is established */
    RUN_FLAG__ASSURE_EST          = 0x00080000,

    RUN_FLAG__TREAT_DROP_AS_IGNORE= 0x00100000,     /* --treat-drop-as-ignore */
    RUN_FLAG__PCAP_RELOAD         = 0x00200000,     /* --pcap-reload */
    RUN_FLAG__TEST                = 0x00400000,     /* -T */
#ifdef SHELL
    RUN_FLAG__SHELL               = 0x00800000,     /* --shell */
#endif
#ifdef PIGLET
    RUN_FLAG__PIGLET              = 0x01000000      /* --piglet */
#endif
};

enum OutputFlag
{
    OUTPUT_FLAG__LINE_BUFFER       = 0x00000001,      /* -f */
    OUTPUT_FLAG__VERBOSE_DUMP      = 0x00000002,      /* -X */
    OUTPUT_FLAG__CHAR_DATA         = 0x00000004,      /* -C */
    OUTPUT_FLAG__APP_DATA          = 0x00000008,      /* -d */

    OUTPUT_FLAG__SHOW_DATA_LINK    = 0x00000010,      /* -e */
    OUTPUT_FLAG__SHOW_WIFI_MGMT    = 0x00000020,      /* -w */
    OUTPUT_FLAG__USE_UTC           = 0x00000040,      /* -U */
    OUTPUT_FLAG__INCLUDE_YEAR      = 0x00000080,      /* -y */

    /* Note using this alters the packet - can't be used inline */
    OUTPUT_FLAG__OBFUSCATE         = 0x00000100,      /* -B */
    OUTPUT_FLAG__ALERT_IFACE       = 0x00000200,      /* -I */
    OUTPUT_FLAG__NO_TIMESTAMP      = 0x00000400,      /* --nostamps */
    OUTPUT_FLAG__ALERTS            = 0x00000800,      /* -A */
};

enum LoggingFlag
{
    LOGGING_FLAG__VERBOSE         = 0x00000001,      /* -v */
    LOGGING_FLAG__QUIET           = 0x00000002,      /* -q */
    LOGGING_FLAG__SYSLOG          = 0x00000004,      /* -M */
    LOGGING_FLAG__SHOW_PLUGINS    = 0x00000008,      // --show-plugins
};

enum TunnelFlags
{
    TUNNEL_GTP    = 0x01,
    TUNNEL_TEREDO = 0x02,
    TUNNEL_6IN4   = 0x04,
    TUNNEL_4IN6   = 0x08
};

struct srmm_table_t;
struct sopg_table_t;
struct PORT_RULE_MAP;
struct SFXHASH;
struct ProfilerConfig;
struct MemoryConfig;
struct LatencyConfig;
struct SFDAQConfig;
class ThreadConfig;

SO_PUBLIC extern THREAD_LOCAL struct SnortConfig* snort_conf;

// SnortState members are updated during runtime. an array in SnortConfig is
// used instead of thread_locals because these must get changed on reload
// FIXIT-L register this data to avoid explicit dependency
struct SnortState
{
    int* pcre_ovector;

    // regex and hs are conditionally built but these are unconditional to
    // avoid compatibility issues with plugins.  if these are conditional
    // then API_OPTIONS must be updated.  note: fwd decls don't work here.
    void* regex_scratch;
    void* hyperscan_scratch;
};

struct SnortConfig
{
public:
    SnortConfig();
    ~SnortConfig();

    void setup();
    bool verify();

    void merge(SnortConfig*);

public:
    //------------------------------------------------------
    // non-reloadable stuff (single instance)
    // FIXIT-L non-reloadable stuff should be made static
    static uint32_t warning_flags;

    //------------------------------------------------------
    // alert module stuff
    bool default_rule_state = true;

    sfip_t homenet;

    //------------------------------------------------------
    // output module stuff
    uint32_t output_flags = 0;
    uint32_t logging_flags = 0;

    uint8_t log_ipv6_extra = 0;
    uint16_t event_trace_max = 0;
    long int tagged_packet_limit = 256;

    std::string log_dir;

    //------------------------------------------------------
    // daq stuff
    SFDAQConfig* daq_config;

    //------------------------------------------------------
    // detection module stuff
    // FIXIT-L pcre_match_limit* are interdependent
    // somehow a packet thread needs a much lower setting
    long int pcre_match_limit = 1500;
    long int pcre_match_limit_recursion = 1500;
    int pcre_ovector_size = 0;

    int asn1_mem = 0;
    uint32_t run_flags = 0;

    //------------------------------------------------------
    // process stuff

    // user_id and group_id should be initialized to -1 by default, because
    // chown() use this later, -1 means no change to user_id/group_id
    int user_id = -1;
    int group_id = -1;

    int dirty_pig = 0;

    std::string chroot_dir;        /* -t or config chroot */
    std::string plugin_path;
    std::vector<std::string> script_paths;

    mode_t file_mask = 0;

    //------------------------------------------------------
    // decode module stuff
    uint8_t mpls_payload_type = 0;
    long int mpls_stack_depth = 0;

    uint8_t enable_teredo = 0;
    uint8_t enable_esp = 0;
    PortBitSet* gtp_ports = nullptr;

    uint8_t num_layers = 0;
    uint8_t max_ip6_extensions = 0;
    uint8_t max_ip_layers = 0;

    //------------------------------------------------------
    // active stuff
    uint8_t respond_attempts = 0;
    uint8_t max_responses = 0;
    uint8_t min_interval = 0;
    uint8_t* eth_dst = nullptr;

    std::string respond_device;
    std::string output;

    //------------------------------------------------------
    // attribute tables stuff
    uint32_t max_attribute_hosts = 0;
    uint32_t max_attribute_services_per_host = 0;
    uint32_t max_metadata_services = 0;

    //------------------------------------------------------
    // packet module stuff
    uint8_t vlan_agnostic = 0;
    uint8_t addressspace_agnostic = 0;

    uint64_t pkt_cnt = 0;           /* -n */
    uint64_t pkt_skip = 0;

    std::string bpf_file;          /* -F or config bpf_file */

    //------------------------------------------------------
    // various modules
    class FastPatternConfig* fast_pattern_config = nullptr;
    struct EventQueueConfig* event_queue_config = nullptr;

    class FileConfig file_config;

    /* XXX XXX policy specific? */
    struct ThresholdConfig* threshold_config = nullptr;
    struct RateFilterConfig* rate_filter_config = nullptr;

    //------------------------------------------------------
    // FIXIT-L command line only stuff, add to conf / module

    uint32_t event_log_id = 0;
    sfip_t obfuscation_net;
    std::string bpf_filter;

    //------------------------------------------------------
    // FIXIT-L non-module stuff - separate config from derived state?
    std::string run_prefix;
    bool id_subdir = false;
    bool id_zero = false;

    bool stdin_rules = false;
    bool obfuscate_pii = false;

    std::string pid_filename;
    std::string orig_log_dir;      /* set in case of chroot */

    int thiszone = 0;

    struct RuleState* rule_state_list = nullptr;
    struct ClassType* classifications = nullptr;
    struct ReferenceSystemNode* references = nullptr;
    struct SFGHASH* otn_map = nullptr;

    struct DetectionFilterConfig* detection_filter_config = nullptr;

    int num_rule_types = 0;
    struct RuleListNode* rule_lists = nullptr;
    int evalOrder[RULE_TYPE__MAX + 1];

    struct FrameworkConfig* framework_config = nullptr;

    /* master port list table */
    struct RulePortTables* port_tables = nullptr;

    /* The port-rule-maps map the src-dst ports to rules for
     * udp and tcp, for Ip we map the dst port as the protocol,
     * and for Icmp we map the dst port to the Icmp type. This
     * allows us to use the decode packet information to in O(1)
     * select a group of rules to apply to the packet.  These
     * rules may or may not have content.  We process the content
     * 1st and then the no content rules for udp/tcp and icmp, and
     * then we process the ip rules. */
    PORT_RULE_MAP* prmIpRTNX = nullptr;
    PORT_RULE_MAP* prmIcmpRTNX = nullptr;
    PORT_RULE_MAP* prmTcpRTNX = nullptr;
    PORT_RULE_MAP* prmUdpRTNX = nullptr;

    srmm_table_t* srmmTable = nullptr;   /* srvc rule map master table */
    srmm_table_t* spgmmTable = nullptr;  /* srvc port_group map master table */
    sopg_table_t* sopgTable = nullptr;   /* service-oridnal to port_group table */

    SFXHASH* detection_option_hash_table = nullptr;
    SFXHASH* detection_option_tree_hash_table = nullptr;

    PolicyMap* policy_map = nullptr;

    uint8_t tunnel_mask = 0;

    struct VarNode* var_list = nullptr;

    //------------------------------------------------------
    ProfilerConfig* profiler = nullptr;

    LatencyConfig* latency = nullptr;
    struct _IntelPmHandles* ipm_handles = nullptr;

    unsigned remote_control = 0;

    MemoryConfig* memory = nullptr;
    //------------------------------------------------------

    SnortState* state = nullptr;
    unsigned num_slots = 0;

    ThreadConfig* thread_config;

    //------------------------------------------------------
    // policy access
    InspectionPolicy* get_inspection_policy()
    { return policy_map->inspection_policy[0]; }

    IpsPolicy* get_ips_policy()
    { return policy_map->ips_policy[0]; }

    NetworkPolicy* get_network_policy()
    { return policy_map->network_policy[0]; }

    // decoding related
    uint8_t get_num_layers() const
    { return num_layers; }

    // curr_layer is the zero based ip6 options
    bool hit_ip6_maxopts(uint8_t curr_opt) const
    { return max_ip6_extensions && (curr_opt >= max_ip6_extensions); }

    // curr_ip is the zero based ip layer
    bool hit_ip_maxlayers(uint8_t curr_ip) const
    { return max_ip_layers && (curr_ip >= max_ip_layers); }

    static long int get_mpls_stack_depth()
    { return snort_conf->mpls_stack_depth; }

    static long int get_mpls_payload_type()
    { return snort_conf->mpls_payload_type; }

    static bool mpls_overlapping_ip()
    { return snort_conf->run_flags & RUN_FLAG__MPLS_OVERLAPPING_IP; }

    static bool mpls_multicast()
    { return snort_conf->run_flags & RUN_FLAG__MPLS_MULTICAST; }

    static bool deep_teredo_inspection()
    { return snort_conf->enable_teredo; }

    static bool gtp_decoding()
    { return snort_conf->gtp_ports; }

    static bool is_gtp_port(uint16_t port)
    { return snort_conf->gtp_ports->test(port); }

    static bool esp_decoding()
    { return snort_conf->enable_esp; }

    // mode related
    static bool test_mode()
    { return snort_conf->run_flags & RUN_FLAG__TEST; }

    static bool daemon_mode()
    { return snort_conf->run_flags & RUN_FLAG__DAEMON; }

    static bool read_mode()
    { return snort_conf->run_flags & RUN_FLAG__READ; }

    static bool inline_mode()
    { return ::get_ips_policy()->policy_mode == POLICY_MODE__INLINE; }

    static bool inline_test_mode()
    { return ::get_ips_policy()->policy_mode == POLICY_MODE__INLINE_TEST; }

    static bool adaptor_inline_mode()
    { return snort_conf->run_flags & RUN_FLAG__INLINE; }

    static bool adaptor_inline_test_mode()
    { return snort_conf->run_flags & RUN_FLAG__INLINE_TEST; }

    // logging stuff
    static bool log_syslog()
    { return snort_conf->logging_flags & LOGGING_FLAG__SYSLOG; }

    static bool log_verbose()
    { return snort_conf->logging_flags & LOGGING_FLAG__VERBOSE; }

    static bool log_quiet()
    { return snort_conf->logging_flags & LOGGING_FLAG__QUIET; }

    // event stuff
    static uint32_t get_event_log_id()
    { return snort_conf->event_log_id; }

    static bool get_log_ip6_extra()
    { return snort_conf->log_ipv6_extra; }

    static bool process_all_events()
    { return snort_conf->event_queue_config->process_all_events; }

    static int get_eval_index(RuleType type)
    { return snort_conf->evalOrder[type]; }

    static int get_default_rule_state()
    { return snort_conf->default_rule_state; }

    static bool tunnel_bypass_enabled(uint8_t proto)
    { return !(snort_conf->tunnel_mask & proto); }

    // checksum stuff
    static bool checksum_drop(uint16_t codec_cksum_err_flag)
    { return ::get_network_policy()->checksum_drop & codec_cksum_err_flag; }

    static bool ip_checksums()
    { return ::get_network_policy()->checksum_eval & CHECKSUM_FLAG__IP; }

    static bool ip_checksum_drops()
    { return ::get_network_policy()->checksum_drop & CHECKSUM_FLAG__IP; }

    static bool udp_checksums()
    { return ::get_network_policy()->checksum_eval & CHECKSUM_FLAG__UDP; }

    static bool udp_checksum_drops()
    { return ::get_network_policy()->checksum_drop & CHECKSUM_FLAG__UDP; }

    static bool tcp_checksums()
    { return ::get_network_policy()->checksum_eval & CHECKSUM_FLAG__TCP; }

    static bool tcp_checksum_drops()
    { return ::get_network_policy()->checksum_drop & CHECKSUM_FLAG__TCP; }

    static bool icmp_checksums()
    { return ::get_network_policy()->checksum_eval & CHECKSUM_FLAG__ICMP; }

    static bool icmp_checksum_drops()
    { return ::get_network_policy()->checksum_drop & CHECKSUM_FLAG__ICMP; }

    // output stuff
    static bool output_include_year()
    { return snort_conf->output_flags & OUTPUT_FLAG__INCLUDE_YEAR; }

    static bool output_use_utc()
    { return snort_conf->output_flags & OUTPUT_FLAG__USE_UTC; }

    static bool output_datalink()
    { return snort_conf->output_flags & OUTPUT_FLAG__SHOW_DATA_LINK; }

    static bool verbose_byte_dump()
    { return snort_conf->output_flags & OUTPUT_FLAG__VERBOSE_DUMP; }

    static bool obfuscate()
    { return snort_conf->output_flags & OUTPUT_FLAG__OBFUSCATE; }

    static bool output_app_data()
    { return snort_conf->output_flags & OUTPUT_FLAG__APP_DATA; }

    static bool output_char_data()
    { return snort_conf->output_flags & OUTPUT_FLAG__CHAR_DATA; }

    static bool alert_interface()
    { return snort_conf->output_flags & OUTPUT_FLAG__ALERT_IFACE; }

    static bool output_no_timestamp()
    { return snort_conf->output_flags & OUTPUT_FLAG__NO_TIMESTAMP; }

    static bool line_buffered_logging()
    { return snort_conf->output_flags & OUTPUT_FLAG__LINE_BUFFER; }

    static bool output_wifi_mgmt()
    { return snort_conf->output_flags & OUTPUT_FLAG__SHOW_WIFI_MGMT; }

    // run flags
    static bool no_lock_pid_file()
    { return snort_conf->run_flags & RUN_FLAG__NO_LOCK_PID_FILE; }

    static bool create_pid_file()
    { return snort_conf->run_flags & RUN_FLAG__CREATE_PID_FILE; }

    static bool pcap_show()
    { return snort_conf->run_flags & RUN_FLAG__PCAP_SHOW; }

    static bool treat_drop_as_alert()
    { return snort_conf->run_flags & RUN_FLAG__TREAT_DROP_AS_ALERT; }

    static bool treat_drop_as_ignore()
    { return snort_conf->run_flags & RUN_FLAG__TREAT_DROP_AS_IGNORE; }

    static bool alert_before_pass()
    { return snort_conf->run_flags & RUN_FLAG__ALERT_BEFORE_PASS; }

    static bool no_pcre()
    { return snort_conf->run_flags & RUN_FLAG__NO_PCRE; }

    static bool conf_error_out()
    { return snort_conf->run_flags & RUN_FLAG__CONF_ERROR_OUT; }

    static bool assure_established()
    { return snort_conf->run_flags & RUN_FLAG__ASSURE_EST; }

    // FIXIT-L snort_conf needed for static hash before initialized
    static bool static_hash()
    { return snort_conf && snort_conf->run_flags & RUN_FLAG__STATIC_HASH; }

    // other stuff
    static uint8_t min_ttl()
    { return ::get_network_policy()->min_ttl; }

    static uint8_t new_ttl()
    { return ::get_network_policy()->new_ttl; }

    static long int get_pcre_match_limit()
    { return snort_conf->pcre_match_limit; }

    static long int get_pcre_match_limit_recursion()
    { return snort_conf->pcre_match_limit_recursion; }

    static const ProfilerConfig* get_profiler()
    { return snort_conf->profiler; }

    static long int get_tagged_packet_limit()
    { return snort_conf->tagged_packet_limit; }

    static uint32_t get_max_attribute_hosts()
    { return snort_conf->max_attribute_hosts; }

    static uint32_t get_max_services_per_host()
    { return snort_conf->max_attribute_services_per_host; }

    static int get_uid()
    { return snort_conf->user_id; }

    static int get_gid()
    { return snort_conf->group_id; }

    static bool get_vlan_agnostic()
    { return snort_conf->vlan_agnostic; }

    static bool address_space_agnostic()
    { return snort_conf->addressspace_agnostic; }

    static bool change_privileges()
    { return snort_conf->user_id != -1 || snort_conf->group_id != -1; }
};

#endif

