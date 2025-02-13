//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <sys/types.h>

#include <list>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "framework/inspector.h"
#include "framework/ips_action.h"
#include "helpers/scratch_allocator.h"
#include "main/policy.h"
#include "sfip/sf_cidr.h"
#include "utils/bits.h"

#define DEFAULT_LOG_DIR "."
#define DEFAULT_PID_FILENAME "snort.pid"

enum RunFlag
{
    RUN_FLAG__READ                = 0x00000001,
    RUN_FLAG__DAEMON              = 0x00000002,
    RUN_FLAG__DUMP_MSG_MAP        = 0x00000004,
    RUN_FLAG__DUMP_RULE_META      = 0x00000008,

    RUN_FLAG__INLINE              = 0x00000010,
    RUN_FLAG__STATIC_HASH         = 0x00000020,
    RUN_FLAG__CREATE_PID_FILE     = 0x00000040,
    RUN_FLAG__NO_LOCK_PID_FILE    = 0x00000080,

    RUN_FLAG__ALERT_BEFORE_PASS   = 0x00000100,
    RUN_FLAG__CONF_ERROR_OUT      = 0x00000200,
    RUN_FLAG__PROCESS_ALL_EVENTS  = 0x00000400,
    RUN_FLAG__INLINE_TEST         = 0x00000800,

    RUN_FLAG__PCAP_SHOW           = 0x00001000,
    RUN_FLAG__SHOW_FILE_CODES     = 0x00002000,
    RUN_FLAG__PAUSE               = 0x00004000,
    RUN_FLAG__NO_PCRE             = 0x00008000,

    RUN_FLAG__DUMP_RULE_STATE     = 0x00010000,
    RUN_FLAG__DUMP_RULE_DEPS      = 0x00020000,
    RUN_FLAG__TEST                = 0x00040000,
    RUN_FLAG__MEM_CHECK           = 0x00080000,

    RUN_FLAG__TRACK_ON_SYN        = 0x00100000,
    RUN_FLAG__IP_FRAGS_ONLY       = 0x00200000,
    RUN_FLAG__TEST_FEATURES       = 0x00400000,
    RUN_FLAG__GEN_DUMP_CONFIG     = 0x00800000,

#ifdef SHELL
    RUN_FLAG__SHELL               = 0x01000000,
#endif
};

enum OutputFlag
{
    OUTPUT_FLAG__LINE_BUFFER       = 0x00000001,
    OUTPUT_FLAG__VERBOSE_DUMP      = 0x00000002,
    OUTPUT_FLAG__CHAR_DATA         = 0x00000004,
    OUTPUT_FLAG__APP_DATA          = 0x00000008,

    OUTPUT_FLAG__SHOW_DATA_LINK    = 0x00000010,
    OUTPUT_FLAG__USE_UTC           = 0x00000020,
    OUTPUT_FLAG__INCLUDE_YEAR      = 0x00000040,
    /* Note using this alters the packet - can't be used inline */
    OUTPUT_FLAG__OBFUSCATE         = 0x00000080,

    OUTPUT_FLAG__ALERT_IFACE       = 0x00000100,
    OUTPUT_FLAG__NO_TIMESTAMP      = 0x00000200,
    OUTPUT_FLAG__ALERTS            = 0x00000400,
    OUTPUT_FLAG__WIDE_HEX          = 0x00000800,

    OUTPUT_FLAG__ALERT_REFS        = 0x00001000,
};

enum LoggingFlag
{
    LOGGING_FLAG__VERBOSE         = 0x00000001,
    LOGGING_FLAG__QUIET           = 0x00000002,
    LOGGING_FLAG__SYSLOG          = 0x00000004,
    LOGGING_FLAG__SHOW_PLUGINS    = 0x00000008,
};

enum TunnelFlags
{
    TUNNEL_GTP    = 0x01,
    TUNNEL_TEREDO = 0x02,
    TUNNEL_6IN4   = 0x04,
    TUNNEL_4IN6   = 0x08,
    TUNNEL_4IN4   = 0x10,
    TUNNEL_6IN6   = 0x20,
    TUNNEL_GRE    = 0x40,
    TUNNEL_MPLS   = 0x80,
    TUNNEL_VXLAN  = 0x100,
    TUNNEL_GENEVE = 0x200
};

enum DumpConfigType
{
    DUMP_CONFIG_NONE = 0,
    DUMP_CONFIG_JSON_ALL,
    DUMP_CONFIG_JSON_TOP,
    DUMP_CONFIG_TEXT
};

class ConfigOutput;
class ControlConn;
class FastPatternConfig;
class RuleStateMap;
class TraceConfig;
class ConfigData;

struct srmm_table_t;
struct sopg_table_t;
struct ClassType;
struct DetectionFilterConfig;
struct EventQueueConfig;
struct FrameworkConfig;
struct HighAvailabilityConfig;
struct IpsActionsConfig;
struct LatencyConfig;
struct MemoryConfig;
struct PayloadInjectorConfig;
struct Plugins;
struct PORT_RULE_MAP;
struct RateFilterConfig;
struct ReferenceSystem;
struct RuleListNode;
struct RulePortTables;
struct SFDAQConfig;
struct SoRules;
struct ThresholdConfig;

namespace snort
{
class GHash;
class ProtocolReference;
class ReloadResourceTuner;
class ThreadConfig;
class XHash;
struct ProfilerConfig;

struct SnortConfig
{
private:
    void init(const SnortConfig* const, ProtocolReference*, const char* exclude_name);

public:
    SnortConfig(const SnortConfig* const other_conf = nullptr, const char* exclude_name = nullptr);
    SnortConfig(ProtocolReference* protocol_reference);
    ~SnortConfig();

    SnortConfig(const SnortConfig&) = delete;

    void setup();
    void post_setup();
    void update_scratch(ControlConn*);
    bool verify() const;

    void merge(const SnortConfig*);
    void clone(const SnortConfig* const);

private:
    static uint32_t logging_flags;

public:
    static uint32_t warning_flags;

    //------------------------------------------------------
    // alert module stuff
    std::string rule_order;

    SfCidr homenet;

    //------------------------------------------------------
    // output module stuff
#ifdef REG_TEST
    // FIXIT-M builtin modules should set SnortConfig defaults instead
    uint32_t output_flags = OUTPUT_FLAG__WIDE_HEX;
#else
    uint32_t output_flags = 0;
#endif
    uint32_t tagged_packet_limit = 256;
    uint16_t event_trace_max = 0;

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
    bool pcre_override = true;

    uint32_t run_flags = 0;

    unsigned offload_limit = 99999;  // disabled
    unsigned offload_threads = 0;    // disabled

    bool hyperscan_literals = false;
    bool pcre_to_regex = false;

    bool global_rule_state = false;
    bool global_default_rule_state = true;
    bool allow_missing_so_rules = false;
    bool enable_strict_reduction = false;
    uint16_t max_continuations = 1024;

    std::unordered_map<std::string, std::vector<std::string>> service_extension =
        {
             { "http", {"http2", "http3"} },
             { "netbios-ssn", {"dcerpc"} },
        };

    //------------------------------------------------------
    // process stuff

    // user_id and group_id should be initialized to -1 by default, because
    // chown() use this later, -1 means no change to user_id/group_id
    int user_id = -1;
    int group_id = -1;
    uint16_t watchdog_timer = 0;
    uint16_t watchdog_min_thread_count = 1;
    bool dirty_pig = false;

    std::string chroot_dir;        /* -t or config chroot */
    std::string include_path;
    std::string plugin_path;
    std::vector<std::string> script_paths;

    mode_t file_mask = 0;

    //------------------------------------------------------
    // decode module stuff
    uint8_t num_layers = 0;
    uint8_t max_ip6_extensions = 0;
    uint8_t max_ip_layers = 0;

    bool enable_esp = false;
    bool address_anomaly_check_enabled = false;

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
    std::string attribute_hosts_file;
    uint32_t max_attribute_hosts = 0;
    uint32_t max_attribute_services_per_host = 0;
    uint32_t max_metadata_services = 0;
    uint32_t segment_count_host = 4;

    //------------------------------------------------------
    // packet module stuff
    bool asid_agnostic = false;
    bool mpls_agnostic = true;
    bool vlan_agnostic = false;

    uint64_t pkt_cnt = 0;           /* -n */
    uint64_t pkt_skip = 0;
    uint64_t pkt_pause_cnt = 0;

    std::string bpf_file;          /* -F or config bpf_file */

    //------------------------------------------------------
    // various modules
    FastPatternConfig* fast_pattern_config = nullptr;
    EventQueueConfig* event_queue_config = nullptr;
    PayloadInjectorConfig* payload_injector_config = nullptr;

    /* policy specific? */
    ThresholdConfig* threshold_config = nullptr;
    RateFilterConfig* rate_filter_config = nullptr;
    DetectionFilterConfig* detection_filter_config = nullptr;

    //------------------------------------------------------
    // FIXIT-L command line only stuff, add to conf / module

    uint16_t event_log_id = 0;
    SfCidr obfuscation_net;
    std::string bpf_filter;
    std::string metadata_filter;

    //------------------------------------------------------
    // FIXIT-L non-module stuff - separate config from derived state?
    std::string run_prefix;
    uint16_t id_offset = 0;
    bool id_subdir = false;
    bool id_zero = false;

    bool stdin_rules = false;

    std::string pid_filename;
    uint8_t max_procs = 1;
    std::string orig_log_dir;      /* set in case of chroot */

    int thiszone = 0;

    std::unordered_map<std::string, ClassType*> classifications;
    std::unordered_map<std::string, ReferenceSystem*> references;

    RuleStateMap* rule_states = nullptr;
    GHash* otn_map = nullptr;

    ProtocolReference* proto_ref = nullptr;

    unsigned num_rule_types = 0;
    RuleListNode* rule_lists = nullptr;
    int* evalOrder = nullptr;

    IpsActionsConfig* ips_actions_config = nullptr;
    FrameworkConfig* framework_config = nullptr;

    /* master port list table */
    RulePortTables* port_tables = nullptr;

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
    sopg_table_t* sopgTable = nullptr;   /* service-ordinal to port_group table */

    XHash* detection_option_hash_table = nullptr;
    XHash* detection_option_tree_hash_table = nullptr;
    XHash* rtn_hash_table = nullptr;

    PolicyMap* policy_map = nullptr;
    std::string tweaks;

    DataBus* global_dbus = nullptr;

    uint16_t tunnel_mask = 0;

    int16_t max_aux_ip = 16;

    // FIXIT-L this is temporary for legacy paf_max required only for HI;
    // it is not appropriate for multiple stream_tcp with different
    // paf_max; the HI splitter should pull from there
    unsigned max_pdu = 16384;

    //------------------------------------------------------
    ProfilerConfig* profiler = nullptr;
    LatencyConfig* latency = nullptr;

    unsigned remote_control_port = 0;
    std::string remote_control_socket;

    MemoryConfig* memory = nullptr;
    //------------------------------------------------------

    std::vector<ScratchAllocator*> scratchers;
    std::vector<void *>* state = nullptr;
    unsigned num_slots = 0;

    ThreadConfig* thread_config;
    HighAvailabilityConfig* ha_config = nullptr;
    TraceConfig* trace_config = nullptr;

    // TraceConfig instance which used by TraceSwap control channel command
    TraceConfig* overlay_trace_config = nullptr;

    //------------------------------------------------------
    //Reload inspector related

    bool cloned = false;
    Plugins* plugins = nullptr;
    SoRules* so_rules = nullptr;

    DumpConfigType dump_config_type = DUMP_CONFIG_NONE;

    std::string dump_config_file;
    std::thread* config_dumper = nullptr;
private:
    std::list<ReloadResourceTuner*> reload_tuners;
    static std::mutex reload_id_mutex;
    unsigned reload_id = 0;
    static std::mutex static_names_mutex;
    static std::unordered_map<std::string, std::string> static_names;

public:
    //------------------------------------------------------
    // decoding related
    uint8_t get_num_layers() const
    { return num_layers; }

    // curr_layer is the zero based ip6 options
    bool hit_ip6_maxopts(uint8_t curr_opt) const
    { return max_ip6_extensions && (curr_opt >= max_ip6_extensions); }

    // curr_ip is the zero based ip layer
    bool hit_ip_maxlayers(uint8_t curr_ip) const
    { return max_ip_layers && (curr_ip >= max_ip_layers); }

    //------------------------------------------------------
    // Non-static mutator methods

    void add_plugin_path(const char*);
    void add_script_path(const char*);
    void enable_syslog();
    void set_alert_before_pass(bool);
    void set_alert_mode(const char*);
    void set_chroot_dir(const char*);
    void set_create_pid_file(bool);
    void set_pid_filename(const char*);
    void set_max_procs(uint8_t);
    void set_daemon(bool);
    void set_decode_data_link(bool);
    void set_dirty_pig(bool);
    void set_dst_mac(const char*);
    void set_dump_chars_only(bool);
    void set_dump_payload(bool);
    void set_dump_payload_verbose(bool);
    void set_gid(const char*);
    void set_log_dir(const char*);
    void set_log_mode(const char*);
    void set_no_logging_timestamps(bool);
    void set_obfuscate(bool);
    void set_obfuscation_mask(const char*);
    void set_overlay_trace_config(TraceConfig*);
    void set_include_path(const char*);
    void set_process_all_events(bool);
    void set_show_year(bool);
    void set_tunnel_verdicts(const char*);
    void set_tweaks(const char*);
    void set_uid(const char*);
    void set_umask(uint32_t);
    void set_utc(bool);
    void set_watchdog(uint16_t);
    void set_watchdog_min_thread_count(uint16_t);
    SO_PUBLIC bool set_packet_latency() const;

    //------------------------------------------------------
    // accessor methods

    bool esp_decoding() const
    { return enable_esp; }

    bool is_address_anomaly_check_enabled() const
    { return address_anomaly_check_enabled; }

    bool aux_ip_is_enabled() const
    { return max_aux_ip >= 0; }

    // mode related
    bool dump_config_mode() const
    { return dump_config_type > DUMP_CONFIG_NONE; }

    bool dump_msg_map() const
    { return run_flags & RUN_FLAG__DUMP_MSG_MAP; }

    bool dump_rule_meta() const
    { return run_flags & RUN_FLAG__DUMP_RULE_META; }

    bool dump_rule_state() const
    { return run_flags & RUN_FLAG__DUMP_RULE_STATE; }

    bool dump_rule_deps() const
    { return run_flags & RUN_FLAG__DUMP_RULE_DEPS; }

    bool dump_rule_info() const
    { return dump_msg_map() or dump_rule_meta() or dump_rule_deps() or dump_rule_state(); }

    bool test_mode() const
    { return run_flags & RUN_FLAG__TEST; }

    bool mem_check() const
    { return run_flags & RUN_FLAG__MEM_CHECK; }

    bool daemon_mode() const
    { return run_flags & RUN_FLAG__DAEMON; }

    bool read_mode() const
    { return run_flags & RUN_FLAG__READ; }

    bool ips_inline_mode() const
    {   
        // cppcheck-suppress nullPointer
        return get_ips_policy()->policy_mode == POLICY_MODE__INLINE; 
    }

    bool ips_inline_test_mode() const
    { return get_ips_policy()->policy_mode == POLICY_MODE__INLINE_TEST; }

    bool nap_inline_mode() const
    { return get_inspection_policy()->policy_mode == POLICY_MODE__INLINE; }

    bool ips_passive_mode() const
    { return get_ips_policy()->policy_mode == POLICY_MODE__PASSIVE; }

    bool show_file_codes() const
    { return run_flags & RUN_FLAG__SHOW_FILE_CODES; }

    bool adaptor_inline_mode() const
    { return run_flags & RUN_FLAG__INLINE; }

    bool adaptor_inline_test_mode() const
    { return run_flags & RUN_FLAG__INLINE_TEST; }

    // event stuff
    uint16_t get_event_log_id() const
    { return event_log_id; }

    int get_eval_index(IpsAction::Type type) const
    { return evalOrder[type]; }

    // output stuff
    bool output_include_year() const
    { return output_flags & OUTPUT_FLAG__INCLUDE_YEAR; }

    bool output_use_utc() const
    { return output_flags & OUTPUT_FLAG__USE_UTC; }

    bool output_datalink() const
    { return output_flags & OUTPUT_FLAG__SHOW_DATA_LINK; }

    bool verbose_byte_dump() const
    { return output_flags & OUTPUT_FLAG__VERBOSE_DUMP; }

    bool obfuscate() const
    { return output_flags & OUTPUT_FLAG__OBFUSCATE; }

    bool output_app_data() const
    { return output_flags & OUTPUT_FLAG__APP_DATA; }

    bool output_char_data() const
    { return output_flags & OUTPUT_FLAG__CHAR_DATA; }

    bool alert_interface() const
    { return output_flags & OUTPUT_FLAG__ALERT_IFACE; }

    bool output_no_timestamp() const
    { return output_flags & OUTPUT_FLAG__NO_TIMESTAMP; }

    bool line_buffered_logging() const
    { return output_flags & OUTPUT_FLAG__LINE_BUFFER; }

    bool output_wide_hex() const
    { return output_flags & OUTPUT_FLAG__WIDE_HEX; }

    bool alert_refs() const
    { return output_flags & OUTPUT_FLAG__ALERT_REFS; }

    // run flags
    bool no_lock_pid_file() const
    { return run_flags & RUN_FLAG__NO_LOCK_PID_FILE; }

    bool create_pid_file() const
    { return run_flags & RUN_FLAG__CREATE_PID_FILE; }

    bool pcap_show() const
    { return run_flags & RUN_FLAG__PCAP_SHOW; }

    bool alert_before_pass() const
    { return run_flags & RUN_FLAG__ALERT_BEFORE_PASS; }

    bool no_pcre() const
    { return run_flags & RUN_FLAG__NO_PCRE; }

    bool conf_error_out() const
    { return run_flags & RUN_FLAG__CONF_ERROR_OUT; }

    bool test_features() const
    { return run_flags & RUN_FLAG__TEST_FEATURES; }

    bool gen_dump_config() const
    { return run_flags & RUN_FLAG__GEN_DUMP_CONFIG; }

    // other stuff
    uint8_t min_ttl() const
    { return get_network_policy()->min_ttl; }

    uint8_t new_ttl() const
    { return get_network_policy()->new_ttl; }

    long int get_pcre_match_limit() const
    { return pcre_match_limit; }

    long int get_pcre_match_limit_recursion() const
    { return pcre_match_limit_recursion; }

    const ProfilerConfig* get_profiler() const
    { return profiler; }

    long int get_tagged_packet_limit() const
    { return tagged_packet_limit; }

    uint32_t get_max_attribute_hosts() const
    { return max_attribute_hosts; }

    uint32_t get_segment_count_host() const
    { return segment_count_host; }

    uint32_t get_max_services_per_host() const
    { return max_attribute_services_per_host; }

    int get_uid() const
    { return user_id; }

    int get_gid() const
    { return group_id; }

    bool get_mpls_agnostic() const
    { return mpls_agnostic; }

    bool get_vlan_agnostic() const
    { return vlan_agnostic; }

    bool address_space_agnostic() const
    { return asid_agnostic; }

    bool change_privileges() const
    { return user_id != -1 || group_id != -1 || !chroot_dir.empty(); }

    bool track_on_syn() const
    { return (run_flags & RUN_FLAG__TRACK_ON_SYN) != 0; }

    bool ip_frags_only() const
    { return (run_flags & RUN_FLAG__IP_FRAGS_ONLY) != 0; }

    void clear_run_flags(RunFlag flag)
    { run_flags &= ~flag; }

    void set_run_flags(RunFlag flag)
    { run_flags |= flag; }

    const std::list<ReloadResourceTuner*>& get_reload_resource_tuners() const
    { return reload_tuners; }

    void clear_reload_resource_tuner_list();

    void update_reload_id();

    unsigned get_reload_id() const
    { return reload_id; }

    void generate_dump(std::list<ConfigData*>*);

    bool get_default_rule_state() const;

    ConfigOutput* create_config_output() const;

    SO_PUBLIC bool tunnel_bypass_enabled(uint16_t proto) const;

    // FIXIT-L snort_conf needed for static hash before initialized
    static bool static_hash()
    { return get_conf() && get_conf()->run_flags & RUN_FLAG__STATIC_HASH; }

    // This requests an entry in the scratch space vector and calls setup /
    // cleanup as appropriate
    SO_PUBLIC static int request_scratch(ScratchAllocator*);
    SO_PUBLIC static void release_scratch(int);

    // runtime access to const config - especially for packet threads
    // prefer access via packet->context->conf
    SO_PUBLIC static const SnortConfig* get_conf();
    // Thread local copy of the reload_id needed for commands that cause reevaluation
    SO_PUBLIC static unsigned get_thread_reload_id();
    SO_PUBLIC static void update_thread_reload_id();

    // runtime access to mutable config - main thread only, and only special cases
    SO_PUBLIC static SnortConfig* get_main_conf();

    static void set_conf(const SnortConfig*);

    SO_PUBLIC void register_reload_handler(ReloadResourceTuner*);

    static void cleanup_fatal_error();

    // logging stuff
    static void enable_log_syslog()
    { logging_flags |= LOGGING_FLAG__SYSLOG; }

    static bool log_syslog()
    { return logging_flags & LOGGING_FLAG__SYSLOG; }

    static void set_log_quiet(bool enabled)
    {
        if (enabled)
            logging_flags |= LOGGING_FLAG__QUIET;
        else
            logging_flags &= ~LOGGING_FLAG__QUIET;
    }

    static bool log_quiet()
    { return logging_flags & LOGGING_FLAG__QUIET; }

    static void enable_log_verbose()
    { logging_flags |= LOGGING_FLAG__VERBOSE; }

    static bool log_verbose()
    { return logging_flags & LOGGING_FLAG__VERBOSE; }

    static void enable_log_show_plugins()
    { logging_flags |= LOGGING_FLAG__SHOW_PLUGINS; }

    static bool log_show_plugins()
    { return logging_flags & LOGGING_FLAG__SHOW_PLUGINS; }

    SO_PUBLIC static const char* get_static_name(const char* name);
    SO_PUBLIC static int get_classification_id(const char* name);
};
}

#endif
