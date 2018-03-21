//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "events/event_queue.h"
#include "framework/bits.h"
#include "main/policy.h"
#include "main/thread.h"
#include "sfip/sf_cidr.h"

#define DEFAULT_LOG_DIR "."

enum RunFlag
{
    RUN_FLAG__READ                = 0x00000001,
    RUN_FLAG__DAEMON              = 0x00000002,
    RUN_FLAG__NO_PROMISCUOUS      = 0x00000004,
    /* UNUSED                       0x00000008 */

    RUN_FLAG__INLINE              = 0x00000010,
    RUN_FLAG__STATIC_HASH         = 0x00000020,
    RUN_FLAG__CREATE_PID_FILE     = 0x00000040,
    RUN_FLAG__NO_LOCK_PID_FILE    = 0x00000080,

    RUN_FLAG__TREAT_DROP_AS_ALERT = 0x00000100,
    RUN_FLAG__ALERT_BEFORE_PASS   = 0x00000200,
    RUN_FLAG__CONF_ERROR_OUT      = 0x00000400,
    RUN_FLAG__MPLS_MULTICAST      = 0x00000800,

    RUN_FLAG__MPLS_OVERLAPPING_IP = 0x00001000,
    RUN_FLAG__PROCESS_ALL_EVENTS  = 0x00002000,
    RUN_FLAG__INLINE_TEST         = 0x00004000,
    RUN_FLAG__PCAP_SHOW           = 0x00008000,

    /* UNUSED                       0x00010000 */
    RUN_FLAG__PAUSE               = 0x00020000,
    RUN_FLAG__NO_PCRE             = 0x00040000,
    /* If stream is configured, the STATEFUL flag is set.  This is
     * somewhat misnamed and is used to assure a session is established */
    RUN_FLAG__ASSURE_EST          = 0x00080000,

    RUN_FLAG__TREAT_DROP_AS_IGNORE= 0x00100000,
    RUN_FLAG__PCAP_RELOAD         = 0x00200000,
    RUN_FLAG__TEST                = 0x00400000,
#ifdef SHELL
    RUN_FLAG__SHELL               = 0x00800000,
#endif
#ifdef PIGLET
    RUN_FLAG__PIGLET              = 0x01000000,
#endif
    RUN_FLAG__MEM_CHECK           = 0x02000000,
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
    TUNNEL_MPLS   = 0x80
};

struct ClassType;
struct srmm_table_t;
struct sopg_table_t;
struct GHash;
struct XHash;
struct MemoryConfig;
struct LatencyConfig;
struct PORT_RULE_MAP;
struct RuleListNode;
struct RulePortTables;
struct RuleState;
struct DetectionFilterConfig;
struct EventQueueConfig;
class FastPatternConfig;
struct FrameworkConfig;
struct ThresholdConfig;
struct RateFilterConfig;
struct SFDAQConfig;
class ThreadConfig;
struct ReferenceSystemNode;
class ProtocolReference;
struct VarNode;
struct _IntelPmHandles;

namespace snort
{
struct ProfilerConfig;

// SnortState members are updated during runtime. an array in SnortConfig is
// used instead of thread_locals because these must get changed on reload
// FIXIT-L register this data to avoid explicit dependency
struct SnortState
{
    int* pcre_ovector;

    // regex hyperscan and sdpattern are conditionally built but these are
    // unconditional to avoid compatibility issues with plugins.  if these are
    // conditional then API_OPTIONS must be updated.
    // note: fwd decls don't work here.
    void* regex_scratch;
    void* hyperscan_scratch;
    void* sdpattern_scratch;
};

struct SnortConfig
{
private:
    void init(const SnortConfig* const, ProtocolReference*);

public:
    SnortConfig(const SnortConfig* const other_conf = nullptr);
    SnortConfig(ProtocolReference* protocol_reference);
    ~SnortConfig();

    SnortConfig(const SnortConfig&) = delete;

    void setup();
    void post_setup();
    bool verify();

    void merge(SnortConfig*);
    void clone(const SnortConfig* const);

public:
    //------------------------------------------------------
    // non-reloadable stuff (single instance)
    // FIXIT-L non-reloadable stuff should be made static
    static uint32_t warning_flags;

    //------------------------------------------------------
    // alert module stuff
    bool default_rule_state = true;

    SfCidr homenet;

    //------------------------------------------------------
    // output module stuff
#ifdef REG_TEST
    // FIXIT-H builtin modules should set SnortConfig defaults instead
    uint32_t output_flags = OUTPUT_FLAG__WIDE_HEX;
#else
    uint32_t output_flags = 0;
#endif
    uint32_t logging_flags = 0;

    uint16_t event_trace_max = 0;
    long int tagged_packet_limit = 256;
    bool enable_packet_trace = false;

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

    unsigned offload_limit = 99999;  // disabled
    unsigned offload_threads = 0;    // disabled

    //------------------------------------------------------
    // process stuff

    // user_id and group_id should be initialized to -1 by default, because
    // chown() use this later, -1 means no change to user_id/group_id
    int user_id = -1;
    int group_id = -1;

    bool dirty_pig = false;

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
    FastPatternConfig* fast_pattern_config = nullptr;
    EventQueueConfig* event_queue_config = nullptr;

    /* XXX XXX policy specific? */
    ThresholdConfig* threshold_config = nullptr;
    RateFilterConfig* rate_filter_config = nullptr;
    DetectionFilterConfig* detection_filter_config = nullptr;

    //------------------------------------------------------
    // FIXIT-L command line only stuff, add to conf / module

    uint32_t event_log_id = 0;
    SfCidr obfuscation_net;
    std::string bpf_filter;

    //------------------------------------------------------
    // FIXIT-L non-module stuff - separate config from derived state?
    std::string run_prefix;
    uint16_t id_offset = 0;
    bool id_subdir = false;
    bool id_zero = false;

    bool stdin_rules = false;
    bool obfuscate_pii = false;

    std::string pid_filename;
    std::string orig_log_dir;      /* set in case of chroot */

    int thiszone = 0;

    RuleState* rule_state_list = nullptr;
    ClassType* classifications = nullptr;
    ReferenceSystemNode* references = nullptr;
    GHash* otn_map = nullptr;

    ProtocolReference* proto_ref = nullptr;

    int num_rule_types = 0;
    RuleListNode* rule_lists = nullptr;
    int evalOrder[Actions::MAX + 1];

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
    VarNode* var_list = nullptr;

    uint8_t tunnel_mask = 0;

    // FIXIT-L this is temporary for legacy paf_max required only for HI;
    // it is not appropriate for multiple stream_tcp with different
    // paf_max; the HI splitter should pull from there
    unsigned max_pdu = 16384;

    //------------------------------------------------------
    ProfilerConfig* profiler = nullptr;

    LatencyConfig* latency = nullptr;
    _IntelPmHandles* ipm_handles = nullptr;

    unsigned remote_control_port = 0;
    std::string remote_control_socket;

    MemoryConfig* memory = nullptr;
    //------------------------------------------------------

    SnortState* state = nullptr;
    unsigned num_slots = 0;

    ThreadConfig* thread_config;

    //------------------------------------------------------
    //Reload inspector related

    bool cloned = false;

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

    void add_script_path(const char*);
    void enable_syslog();
    void set_alert_before_pass(bool);
    void set_alert_mode(const char*);
    void set_chroot_dir(const char*);
    void set_create_pid_file(bool);
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
    void set_plugin_path(const char*);
    void set_process_all_events(bool);
    void set_quiet(bool);
    void set_show_year(bool);
    void set_tunnel_verdicts(const char*);
    void set_treat_drop_as_alert(bool);
    void set_treat_drop_as_ignore(bool);
    void set_uid(const char*);
    void set_umask(const char*);
    void set_utc(bool);
    void set_verbose(bool);
    void free_rule_state_list();

    //------------------------------------------------------
    // Static convenience accessor methods

    static long int get_mpls_stack_depth()
    { return get_conf()->mpls_stack_depth; }

    static long int get_mpls_payload_type()
    { return get_conf()->mpls_payload_type; }

    static bool mpls_overlapping_ip()
    { return get_conf()->run_flags & RUN_FLAG__MPLS_OVERLAPPING_IP; }

    static bool mpls_multicast()
    { return get_conf()->run_flags & RUN_FLAG__MPLS_MULTICAST; }

    static bool deep_teredo_inspection()
    { return get_conf()->enable_teredo; }

    static bool gtp_decoding()
    { return get_conf()->gtp_ports; }

    static bool is_gtp_port(uint16_t port)
    { return get_conf()->gtp_ports->test(port); }

    static bool esp_decoding()
    { return get_conf()->enable_esp; }

    // mode related
    static bool test_mode()
    { return get_conf()->run_flags & RUN_FLAG__TEST; }

    static bool mem_check()
    { return get_conf()->run_flags & RUN_FLAG__MEM_CHECK; }

    static bool daemon_mode()
    { return get_conf()->run_flags & RUN_FLAG__DAEMON; }

    static bool read_mode()
    { return get_conf()->run_flags & RUN_FLAG__READ; }

    static bool inline_mode()
    { return snort::get_ips_policy()->policy_mode == POLICY_MODE__INLINE; }

    static bool inline_test_mode()
    { return snort::get_ips_policy()->policy_mode == POLICY_MODE__INLINE_TEST; }

    static bool adaptor_inline_mode()
    { return get_conf()->run_flags & RUN_FLAG__INLINE; }

    static bool adaptor_inline_test_mode()
    { return get_conf()->run_flags & RUN_FLAG__INLINE_TEST; }

    // logging stuff
    static bool log_syslog()
    { return get_conf()->logging_flags & LOGGING_FLAG__SYSLOG; }

    static bool log_verbose()
    { return get_conf()->logging_flags & LOGGING_FLAG__VERBOSE; }

    static bool log_quiet()
    { return get_conf()->logging_flags & LOGGING_FLAG__QUIET; }

    // event stuff
    static uint32_t get_event_log_id()
    { return get_conf()->event_log_id; }

    static bool process_all_events()
    { return get_conf()->event_queue_config->process_all_events; }

    static int get_eval_index(Actions::Type type)
    { return get_conf()->evalOrder[type]; }

    static int get_default_rule_state()
    { return get_conf()->default_rule_state; }

    SO_PUBLIC static bool tunnel_bypass_enabled(uint8_t proto);

    // checksum stuff
    static bool checksum_drop(uint16_t codec_cksum_err_flag)
    { return snort::get_network_policy()->checksum_drop & codec_cksum_err_flag; }

    static bool ip_checksums()
    { return snort::get_network_policy()->checksum_eval & CHECKSUM_FLAG__IP; }

    static bool ip_checksum_drops()
    { return snort::get_network_policy()->checksum_drop & CHECKSUM_FLAG__IP; }

    static bool udp_checksums()
    { return snort::get_network_policy()->checksum_eval & CHECKSUM_FLAG__UDP; }

    static bool udp_checksum_drops()
    { return snort::get_network_policy()->checksum_drop & CHECKSUM_FLAG__UDP; }

    static bool tcp_checksums()
    { return snort::get_network_policy()->checksum_eval & CHECKSUM_FLAG__TCP; }

    static bool tcp_checksum_drops()
    { return snort::get_network_policy()->checksum_drop & CHECKSUM_FLAG__TCP; }

    static bool icmp_checksums()
    { return snort::get_network_policy()->checksum_eval & CHECKSUM_FLAG__ICMP; }

    static bool icmp_checksum_drops()
    { return snort::get_network_policy()->checksum_drop & CHECKSUM_FLAG__ICMP; }

    // output stuff
    static bool output_include_year()
    { return get_conf()->output_flags & OUTPUT_FLAG__INCLUDE_YEAR; }

    static bool output_use_utc()
    { return get_conf()->output_flags & OUTPUT_FLAG__USE_UTC; }

    static bool output_datalink()
    { return get_conf()->output_flags & OUTPUT_FLAG__SHOW_DATA_LINK; }

    static bool verbose_byte_dump()
    { return get_conf()->output_flags & OUTPUT_FLAG__VERBOSE_DUMP; }

    static bool obfuscate()
    { return get_conf()->output_flags & OUTPUT_FLAG__OBFUSCATE; }

    static bool output_app_data()
    { return get_conf()->output_flags & OUTPUT_FLAG__APP_DATA; }

    static bool output_char_data()
    { return get_conf()->output_flags & OUTPUT_FLAG__CHAR_DATA; }

    static bool alert_interface()
    { return get_conf()->output_flags & OUTPUT_FLAG__ALERT_IFACE; }

    static bool output_no_timestamp()
    { return get_conf()->output_flags & OUTPUT_FLAG__NO_TIMESTAMP; }

    static bool line_buffered_logging()
    { return get_conf()->output_flags & OUTPUT_FLAG__LINE_BUFFER; }

    static bool output_wide_hex()
    { return get_conf()->output_flags & OUTPUT_FLAG__WIDE_HEX; }

    static bool alert_refs()
    { return get_conf()->output_flags & OUTPUT_FLAG__ALERT_REFS; }

    // run flags
    static bool no_lock_pid_file()
    { return get_conf()->run_flags & RUN_FLAG__NO_LOCK_PID_FILE; }

    static bool create_pid_file()
    { return get_conf()->run_flags & RUN_FLAG__CREATE_PID_FILE; }

    static bool pcap_show()
    { return get_conf()->run_flags & RUN_FLAG__PCAP_SHOW; }

    static bool treat_drop_as_alert()
    { return get_conf()->run_flags & RUN_FLAG__TREAT_DROP_AS_ALERT; }

    static bool treat_drop_as_ignore()
    { return get_conf()->run_flags & RUN_FLAG__TREAT_DROP_AS_IGNORE; }

    static bool alert_before_pass()
    { return get_conf()->run_flags & RUN_FLAG__ALERT_BEFORE_PASS; }

    static bool no_pcre()
    { return get_conf()->run_flags & RUN_FLAG__NO_PCRE; }

    static bool conf_error_out()
    { return get_conf()->run_flags & RUN_FLAG__CONF_ERROR_OUT; }

    static bool assure_established()
    { return get_conf()->run_flags & RUN_FLAG__ASSURE_EST; }

    // FIXIT-L snort_conf needed for static hash before initialized
    static bool static_hash()
    { return get_conf() && get_conf()->run_flags & RUN_FLAG__STATIC_HASH; }

    // other stuff
    static uint8_t min_ttl()
    { return snort::get_network_policy()->min_ttl; }

    static uint8_t new_ttl()
    { return snort::get_network_policy()->new_ttl; }

    static long int get_pcre_match_limit()
    { return get_conf()->pcre_match_limit; }

    static long int get_pcre_match_limit_recursion()
    { return get_conf()->pcre_match_limit_recursion; }

    static const ProfilerConfig* get_profiler()
    { return get_conf()->profiler; }

    static long int get_tagged_packet_limit()
    { return get_conf()->tagged_packet_limit; }

    static uint32_t get_max_attribute_hosts()
    { return get_conf()->max_attribute_hosts; }

    static uint32_t get_max_services_per_host()
    { return get_conf()->max_attribute_services_per_host; }

    static int get_uid()
    { return get_conf()->user_id; }

    static int get_gid()
    { return get_conf()->group_id; }

    static bool get_vlan_agnostic()
    { return get_conf()->vlan_agnostic; }

    static bool address_space_agnostic()
    { return get_conf()->addressspace_agnostic; }

    static bool change_privileges()
    {
        return get_conf()->user_id != -1 || get_conf()->group_id != -1 ||
            !get_conf()->chroot_dir.empty();
    }

    static bool packet_trace_enabled()
    {
        return get_conf()->enable_packet_trace;
    }

    // Use this to access current thread's conf from other units
    static void set_conf(SnortConfig*);

    SO_PUBLIC static SnortConfig* get_conf();
};
}

#endif

