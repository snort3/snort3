//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "snort_config.h"

#include <grp.h>
#include <pwd.h>
#include <syslog.h>

#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/fp_config.h"
#include "detection/fp_create.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/sfthreshold.h"
#include "helpers/process.h"
#include "ips_options/ips_pcre.h"
#include "latency/latency_config.h"
#include "log/messages.h"
#include "managers/event_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "managers/mpse_manager.h"
#include "memory/memory_config.h"
#include "packet_io/sfdaq_config.h"
#include "parser/parser.h"
#include "parser/vars.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "target_based/sftarget_reader.h"
#include "target_based/snort_protocols.h"
#include "utils/dnet_header.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#ifdef HAVE_HYPERSCAN
#include "ips_options/ips_regex.h"
#include "ips_options/ips_sd_pattern.h"
#include "search_engines/hyperscan.h"
#endif

#include "snort.h"
#include "thread_config.h"

#define LOG_NONE    "none"
#define LOG_DUMP    "dump"
#define LOG_CODECS  "codecs"

#define ALERT_NONE  "none"
#define ALERT_CMG   "cmg"
#define ALERT_JH    "jh"
#define ALERT_DJR   "djr"
#define ALERT_U2    "u2"
#define ALERT_AJK   "ajk"

#define OUTPUT_U2   "unified2"
#define OUTPUT_FAST "alert_fast"

THREAD_LOCAL SnortConfig* snort_conf = nullptr;
uint32_t SnortConfig::warning_flags = 0;

//-------------------------------------------------------------------------
// private implementation
//-------------------------------------------------------------------------

static void FreeClassifications(ClassType* head)
{
    while ( head )
    {
        ClassType* tmp = head;
        head = head->next;

        if ( tmp->name )
            snort_free(tmp->name);

        if ( tmp->type )
            snort_free(tmp->type);

        snort_free(tmp);
    }
}

static void FreeReferences(ReferenceSystemNode* head)
{
    while ( head )
    {
        ReferenceSystemNode* tmp = head;
        head = head->next;

        if ( tmp->name )
            snort_free(tmp->name);

        if ( tmp->url )
            snort_free(tmp->url);

        snort_free(tmp);
    }
}

static void init_policy_mode(IpsPolicy* p)
{
    switch ( p->policy_mode )
    {
    case POLICY_MODE__PASSIVE:
        if ( SnortConfig::adaptor_inline_test_mode() )
            p->policy_mode = POLICY_MODE__INLINE_TEST;
        break;

    case POLICY_MODE__INLINE:
        if ( SnortConfig::adaptor_inline_test_mode() )
            p->policy_mode = POLICY_MODE__INLINE_TEST;

        else if (!SnortConfig::adaptor_inline_mode())
        {
            ParseWarning(WARN_DAQ, "adapter is in passive mode; switching policy mode to tap.");
            p->policy_mode = POLICY_MODE__PASSIVE;
        }
        break;

    case POLICY_MODE__INLINE_TEST:
        break;

    case POLICY_MODE__MAX:
        if ( SnortConfig::adaptor_inline_mode() )
            p->policy_mode = POLICY_MODE__INLINE;
        else
            p->policy_mode = POLICY_MODE__PASSIVE;
        break;
    }
}

static void init_policies(SnortConfig* sc)
{
    for ( auto p : sc->policy_map->ips_policy )
        init_policy_mode(p);
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

/* A lot of this initialization can be skipped if not running in IDS mode
 * but the goal is to minimize config checks at run time when running in
 * IDS mode so we keep things simple and enforce that the only difference
 * among run_modes is how we handle packets via the log_func. */
SnortConfig::SnortConfig()
{
    num_layers = DEFAULT_LAYERMAX;

    max_attribute_hosts = DEFAULT_MAX_ATTRIBUTE_HOSTS;
    max_attribute_services_per_host = DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST;

    max_metadata_services = DEFAULT_MAX_METADATA_SERVICES;
    mpls_stack_depth = DEFAULT_LABELCHAIN_LENGTH;

    daq_config = new SFDAQConfig();
    InspectorManager::new_config(this);

    num_slots = ThreadConfig::get_instance_max();
    state = (SnortState*)snort_calloc(num_slots, sizeof(SnortState));

    profiler = new ProfilerConfig;
    latency = new LatencyConfig();
    memory = new MemoryConfig();
    policy_map = new PolicyMap;
    thread_config = new ThreadConfig();

    homenet.clear();
    obfuscation_net.clear();

    memset(evalOrder, 0, sizeof(evalOrder));
    proto_ref = new ProtocolReference;
}

SnortConfig::~SnortConfig()
{
    free_rule_state_list();
    FreeClassifications(classifications);
    FreeReferences(references);

#ifdef HAVE_HYPERSCAN
    hyperscan_cleanup(this);
    sdpattern_cleanup(this);
    regex_cleanup(this);
#endif
    pcre_cleanup(this);

    FreeRuleLists(this);
    OtnLookupFree(otn_map);
    PortTablesFree(port_tables);

    ThresholdConfigFree(threshold_config);
    RateFilter_ConfigFree(rate_filter_config);
    DetectionFilterConfigFree(detection_filter_config);

    if ( event_queue_config )
        EventQueueConfigFree(event_queue_config);

    fpDeleteFastPacketDetection(this);

    if (eth_dst )
        snort_free(eth_dst);

    if ( var_list )
        FreeVarList(var_list);

    if ( fast_pattern_config &&
        (!snort_conf || this == snort_conf ||
        (fast_pattern_config->get_search_api() !=
        snort_conf->fast_pattern_config->get_search_api())) )
    {
        MpseManager::stop_search_engine(fast_pattern_config->get_search_api());
    }
    delete fast_pattern_config;

    delete policy_map;
    InspectorManager::delete_config(this);

    snort_free(state);
    delete thread_config;

    if (gtp_ports)
        delete gtp_ports;

    delete profiler;
    delete latency;
    delete memory;
    delete daq_config;
    delete proto_ref;

    trim_heap();
}

void SnortConfig::setup()
{
    if ( output_use_utc() )
        thiszone = 0;

    else
        thiszone = gmt2local(0);

    init_policies(this);
    ParseRules(this);

    // FIXIT-L see SnortInit() on config printing
    //detection_filter_print_config(detection_filter_config);
    //RateFilter_PrintConfig(rate_filter_config);
    //print_thresholding(threshold_config, 0);
    //PrintRuleOrder(rule_lists);

    SetRuleStates(this);

    /* Need to do this after dynamic detection stuff is initialized, too */
    IpsManager::verify(this);
    ModuleManager::load_commands(policy_map->get_shell());

    fpCreateFastPacketDetection(this);
}

void SnortConfig::post_setup()
{
    // FIXIT-L register setup and cleanup  to eliminate explicit calls and
    // allow pcre, regex, and hyperscan to be built dynamically. Hyperscan setup
    // moved to post_setup to ensure all the prep_patterns are called before it.
    pcre_setup(this);
#ifdef HAVE_HYPERSCAN
    regex_setup(this);
    sdpattern_setup(this);
    hyperscan_setup(this);
#endif
}

// merge in everything from the command line config
void SnortConfig::merge(SnortConfig* cmd_line)
{
    if ( !cmd_line->log_dir.empty() )
        log_dir = cmd_line->log_dir;

    if ( log_dir.empty() )
        log_dir = DEFAULT_LOG_DIR;

    run_prefix = cmd_line->run_prefix;
    id_subdir = cmd_line->id_subdir;
    id_zero = cmd_line->id_zero;

    /* Used because of a potential chroot */
    orig_log_dir = log_dir;
    event_log_id = cmd_line->event_log_id;

    run_flags |= cmd_line->run_flags;
    output_flags |= cmd_line->output_flags;
    logging_flags |= cmd_line->logging_flags;

    stdin_rules = cmd_line->stdin_rules;

    // only set by cmd_line to override other conf output settings
    output = cmd_line->output;

    /* Merge checksum flags.  If command line modified them, use from the
     * command line, else just use from config_file. */

    int cl_chk = cmd_line->get_network_policy()->checksum_eval;
    int cl_drop = cmd_line->get_network_policy()->checksum_drop;

    for ( auto p : policy_map->network_policy )
    {
        if ( !(cl_chk & CHECKSUM_FLAG__DEF) )
            p->checksum_eval = cl_chk;

        if ( !(cl_drop & CHECKSUM_FLAG__DEF) )
            p->checksum_drop = cl_drop;
    }

    /* FIXIT-L do these belong in network policy? */
    if (cmd_line->num_layers != 0)
        num_layers = cmd_line->num_layers;

    if (cmd_line->max_ip6_extensions != 0)
        max_ip6_extensions = cmd_line->max_ip6_extensions;

    if (cmd_line->max_ip_layers != 0)
        max_ip_layers = cmd_line->max_ip_layers;

    if (cmd_line->obfuscation_net.get_family() != 0)
        memcpy(&obfuscation_net, &cmd_line->obfuscation_net, sizeof(obfuscation_net));

    if (cmd_line->homenet.get_family() != 0)
        memcpy(&homenet, &cmd_line->homenet, sizeof(homenet));

    if ( !cmd_line->bpf_file.empty() )
        bpf_file = cmd_line->bpf_file;

    if ( !cmd_line->bpf_filter.empty() )
        bpf_filter = cmd_line->bpf_filter;

    if (cmd_line->pkt_cnt != 0)
        pkt_cnt = cmd_line->pkt_cnt;

    if (cmd_line->pkt_skip != 0)
        pkt_skip = cmd_line->pkt_skip;

    if (cmd_line->group_id != -1)
        group_id = cmd_line->group_id;

    if (cmd_line->user_id != -1)
        user_id = cmd_line->user_id;

    /* Only configurable on command line */
    if (cmd_line->file_mask != 0)
        file_mask = cmd_line->file_mask;

    if ( !cmd_line->chroot_dir.empty() )
    {
        chroot_dir = cmd_line->chroot_dir;
    }

    if ( cmd_line->dirty_pig )
        dirty_pig = cmd_line->dirty_pig;

    daq_config->overlay(cmd_line->daq_config);

    if (cmd_line->mpls_stack_depth != DEFAULT_LABELCHAIN_LENGTH)
        mpls_stack_depth = cmd_line->mpls_stack_depth;

    /* Set MPLS payload type here if it hasn't been defined */
    if ((cmd_line->mpls_payload_type == 0) &&
        (mpls_payload_type == 0))
    {
        mpls_payload_type = DEFAULT_MPLS_PAYLOADTYPE;
    }
    else if (cmd_line->mpls_payload_type != 0)
    {
        mpls_payload_type = cmd_line->mpls_payload_type;
    }

    if (cmd_line->run_flags & RUN_FLAG__PROCESS_ALL_EVENTS)
        event_queue_config->process_all_events = 1;

#ifdef SHELL
    if ( cmd_line->remote_control_port )
        remote_control_port = cmd_line->remote_control_port;
    else if ( !cmd_line->remote_control_socket.empty() )
        remote_control_socket = cmd_line->remote_control_socket;
#endif

    // config file vars are stored differently
    // FIXIT-M should cmd_line use the same var list / table?
    var_list = NULL;

    snort_free(state);
    num_slots = ThreadConfig::get_instance_max();
    state = (SnortState*)snort_calloc(num_slots, sizeof(SnortState));
}

bool SnortConfig::verify()
{
    if (snort_conf->asn1_mem != asn1_mem)
    {
        ErrorMessage("Snort Reload: Changing the asn1 memory configuration "
            "requires a restart.\n");
        return false;
    }

    if ( bpf_filter != snort_conf->bpf_filter )
    {
        ErrorMessage("Snort Reload: Changing the bpf filter configuration "
            "requires a restart.\n");
        return false;
    }

    if ( respond_attempts != snort_conf->respond_attempts ||
        respond_device != snort_conf->respond_device )
    {
        ErrorMessage("Snort Reload: Changing config response "
            "requires a restart.\n");
        return false;
    }

    if (snort_conf->chroot_dir != chroot_dir)
    {
        ErrorMessage("Snort Reload: Changing the chroot directory "
            "configuration requires a restart.\n");
        return false;
    }

    if ((snort_conf->run_flags & RUN_FLAG__DAEMON) !=
        (run_flags & RUN_FLAG__DAEMON))
    {
        ErrorMessage("Snort Reload: Changing to or from daemon mode "
            "requires a restart.\n");
        return false;
    }

    /* Orig log dir because a chroot might have changed it */
    if (snort_conf->orig_log_dir != orig_log_dir)
    {
        ErrorMessage("Snort Reload: Changing the log directory "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->max_attribute_hosts != max_attribute_hosts)
    {
        ErrorMessage("Snort Reload: Changing max_attribute_hosts "
            "configuration requires a restart.\n");
        return false;
    }
    if (snort_conf->max_attribute_services_per_host != max_attribute_services_per_host)
    {
        ErrorMessage("Snort Reload: Changing max_attribute_services_per_host "
            "configuration requires a restart.\n");
        return false;
    }

    if ((snort_conf->run_flags & RUN_FLAG__NO_PROMISCUOUS) !=
        (run_flags & RUN_FLAG__NO_PROMISCUOUS))
    {
        ErrorMessage("Snort Reload: Changing to or from promiscuous mode "
            "requires a restart.\n");
        return false;
    }

    if (snort_conf->group_id != group_id)
    {
        ErrorMessage("Snort Reload: Changing the group id "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->user_id != user_id)
    {
        ErrorMessage("Snort Reload: Changing the user id "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->daq_config->mru_size != daq_config->mru_size)
    {
        ErrorMessage("Snort Reload: Changing the packet snaplen "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->threshold_config->memcap !=
        threshold_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the threshold memcap "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->rate_filter_config->memcap !=
        rate_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the rate filter memcap "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->detection_filter_config->memcap !=
        detection_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the detection filter memcap "
            "configuration requires a restart.\n");
        return false;
    }

    return true;
}

void SnortConfig::set_alert_before_pass(bool enabled)
{
    if (enabled)
        run_flags |= RUN_FLAG__ALERT_BEFORE_PASS;
    else
        run_flags &= ~RUN_FLAG__ALERT_BEFORE_PASS;
}

void SnortConfig::set_chroot_dir(const char* directory)
{
    if (directory)
        chroot_dir = directory;
    else
        chroot_dir.clear();
}

void SnortConfig::set_create_pid_file(bool enabled)
{
    if (enabled)
        run_flags |= RUN_FLAG__CREATE_PID_FILE;
    else
        run_flags &= ~RUN_FLAG__CREATE_PID_FILE;
}

void SnortConfig::set_daemon(bool enabled)
{
    if (enabled)
    {
        DebugMessage(DEBUG_INIT, "Daemon mode flag set\n");
        run_flags |= RUN_FLAG__DAEMON;
    }
    else
        run_flags &= ~RUN_FLAG__DAEMON;
}

void SnortConfig::set_decode_data_link(bool enabled)
{
    if (enabled)
    {
        DebugMessage(DEBUG_INIT, "Decode DLL set\n");
        output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
    }
    else
        output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
}

void SnortConfig::set_dump_chars_only(bool enabled)
{
    if (enabled)
    {
        /* dump the application layer as text only */
        DebugMessage(DEBUG_INIT, "Character payload dump set\n");
        output_flags |= OUTPUT_FLAG__CHAR_DATA;
    }
    else
        output_flags &= ~OUTPUT_FLAG__CHAR_DATA;
}

void SnortConfig::set_dump_payload(bool enabled)
{
    if (enabled)
    {
        /* dump the application layer */
        DebugMessage(DEBUG_INIT, "Payload dump set\n");
        output_flags |= OUTPUT_FLAG__APP_DATA;
    }
    else
        output_flags &= ~OUTPUT_FLAG__APP_DATA;
}

void SnortConfig::set_dump_payload_verbose(bool enabled)
{
    if (enabled)
    {
        DebugMessage(DEBUG_INIT, "Verbose packet bytecode dumps enabled\n");
        output_flags |= OUTPUT_FLAG__VERBOSE_DUMP;
    }
    else
        output_flags &= ~OUTPUT_FLAG__VERBOSE_DUMP;
}

void SnortConfig::set_dst_mac(const char* mac_addr)
{
    if (mac_addr)
    {
        eth_addr_t dst;

        if (eth_pton(mac_addr, &dst) < 0)
        {
            ParseError("Format check failed: %s,  Use format like 12:34:56:78:90:1a", mac_addr);
            return;
        }
        free(eth_dst);
        eth_dst = (uint8_t*) snort_calloc(sizeof(dst.data));
        memcpy(eth_dst, dst.data, sizeof(dst.data));
    }
    else
    {
        free(eth_dst);
        eth_dst = nullptr;
    }
}

void SnortConfig::set_log_dir(const char* directory)
{
    if (directory)
        log_dir = directory;
    else
        log_dir.clear();
}

void SnortConfig::set_dirty_pig(bool enabled)
{
    dirty_pig = enabled;
}

void SnortConfig::set_obfuscate(bool enabled)
{
    if (enabled)
        output_flags |= OUTPUT_FLAG__OBFUSCATE;
    else
        output_flags &= ~OUTPUT_FLAG__OBFUSCATE;
}

void SnortConfig::set_no_logging_timestamps(bool enabled)
{
    if (enabled)
        output_flags |= OUTPUT_FLAG__NO_TIMESTAMP;
    else
        output_flags &= ~OUTPUT_FLAG__NO_TIMESTAMP;
}

void SnortConfig::set_obfuscation_mask(const char* mask)
{
   if (!mask)
        return;

    DebugFormat(DEBUG_INIT, "Got obfus data: %s\n", mask);

    output_flags |= OUTPUT_FLAG__OBFUSCATE;

    obfuscation_net.set(mask);
}

void SnortConfig::set_quiet(bool enabled)
{
    if (enabled)
        logging_flags |= LOGGING_FLAG__QUIET;
    else
        logging_flags &= ~LOGGING_FLAG__QUIET;
}

void SnortConfig::set_gid(const char* args)
{
    struct group* gr;
    long target_gid;
    char* endptr;

    if (!args)
        return;

    target_gid = SnortStrtol(args, &endptr, 10);
    if (*endptr != '\0')
        gr = getgrnam(args); // main thread only
    else if (errno == ERANGE || target_gid < 0)
    {
        ParseError("group id '%s' out of range.", args);
        return;
    }
    else
        gr = getgrgid((gid_t) target_gid); // main thread only

    if (!gr)
    {
        ParseError("group '%s' unknown.", args);
        return;
    }

    /* If we're already running as the desired group ID, don't bother to try changing it later. */
    if (gr->gr_gid != getgid())
        group_id = (int) gr->gr_gid;
}

void SnortConfig::set_uid(const char* args)
{
    struct passwd* pw;
    long target_uid;
    char* endptr;

    if (!args)
        return;

    target_uid = SnortStrtol(args, &endptr, 10);
    if (*endptr != '\0')
        pw = getpwnam(args); // main thread only
    else if (errno == ERANGE || target_uid < 0)
    {
        ParseError("user id '%s' out of range.", args);
        return;
    }
    else
        pw = getpwuid((uid_t) target_uid); // main thread only

    if (!pw)
    {
        ParseError("user '%s' unknown.", args);
        return;
    }

    /* Set group ID to user's default group if not already set.
       If we're already running as the desired user and/or group ID,
       don't bother to try changing it later. */
    if (pw->pw_uid != getuid())
        user_id = (int) pw->pw_uid;

    if (group_id == -1 && pw->pw_gid != getgid())
        group_id = (int) pw->pw_gid;

    DebugFormat(DEBUG_INIT, "UserID: %d GroupID: %d.\n", user_id, group_id);
}

void SnortConfig::set_show_year(bool enabled)
{
    if (enabled)
    {
        output_flags |= OUTPUT_FLAG__INCLUDE_YEAR;
        DebugMessage(DEBUG_INIT, "Enabled year in timestamp\n");
    }
    else
        output_flags &= ~OUTPUT_FLAG__INCLUDE_YEAR;
}

void SnortConfig::set_treat_drop_as_alert(bool enabled)
{
    if (enabled)
        run_flags |= RUN_FLAG__TREAT_DROP_AS_ALERT;
    else
        run_flags &= ~RUN_FLAG__TREAT_DROP_AS_ALERT;
}

void SnortConfig::set_treat_drop_as_ignore(bool enabled)
{
    if (enabled)
        run_flags |= RUN_FLAG__TREAT_DROP_AS_IGNORE;
    else
        run_flags &= ~RUN_FLAG__TREAT_DROP_AS_IGNORE;
}

void SnortConfig::set_process_all_events(bool enabled)
{
    if (enabled)
        run_flags |= RUN_FLAG__PROCESS_ALL_EVENTS;
    else
        run_flags &= ~RUN_FLAG__PROCESS_ALL_EVENTS;
}

#ifdef ACCESSPERMS
# define FILE_ACCESS_BITS ACCESSPERMS
#else
# ifdef S_IAMB
#  define FILE_ACCESS_BITS S_IAMB
# else
#  define FILE_ACCESS_BITS 0x1FF
# endif
#endif

void SnortConfig::set_umask(const char* args)
{
    char* endptr;
    long mask = SnortStrtol(args, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0') ||
        (mask < 0) || (mask & ~FILE_ACCESS_BITS))
    {
        ParseError("bad umask: %s", args);
    }
    file_mask = (mode_t)mask;
}

void SnortConfig::set_utc(bool enabled)
{
    if (enabled)
        output_flags |= OUTPUT_FLAG__USE_UTC;
    else
        output_flags &= ~OUTPUT_FLAG__USE_UTC;
}

void SnortConfig::set_verbose(bool enabled)
{
    if (enabled)
    {
        logging_flags |= LOGGING_FLAG__VERBOSE;
        DebugMessage(DEBUG_INIT, "Verbose Flag active\n");
    }
    else
        logging_flags &= ~LOGGING_FLAG__VERBOSE;
}

void SnortConfig::set_tunnel_verdicts(const char* args)
{
    char* tmp, * tok;

    tmp = snort_strdup(args);
    char* lasts = { 0 };
    tok = strtok_r(tmp, " ,", &lasts);

    while (tok)
    {
        if (!strcasecmp(tok, "gtp"))
            tunnel_mask |= TUNNEL_GTP;

        else if (!strcasecmp(tok, "teredo"))
            tunnel_mask |= TUNNEL_TEREDO;

        else if (!strcasecmp(tok, "6in4"))
            tunnel_mask |= TUNNEL_6IN4;

        else if (!strcasecmp(tok, "4in6"))
            tunnel_mask |= TUNNEL_4IN6;

        else
        {
            ParseError("unknown tunnel bypass protocol");
            return;
        }

        tok = strtok_r(NULL, " ,", &lasts);
    }
    snort_free(tmp);
}

void SnortConfig::set_plugin_path(const char* path)
{
    if (path)
        plugin_path = path;
    else
        plugin_path.clear();
}

void SnortConfig::add_script_path(const char* path)
{
    if (path)
        script_paths.push_back(path);
}

void SnortConfig::set_alert_mode(const char* val)
{
    if (strcasecmp(val, ALERT_NONE) == 0)
        EventManager::enable_alerts(false);

    else if ( !strcasecmp(val, ALERT_CMG) or !strcasecmp(val, ALERT_JH) or
        !strcasecmp(val, ALERT_DJR) )
    {
        output = OUTPUT_FAST;
        output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
        output_flags |= OUTPUT_FLAG__APP_DATA;
    }
    else if ( !strcasecmp(val, ALERT_U2) or !strcasecmp(val, ALERT_AJK) )
        output = OUTPUT_U2;

    else
        output = val;

    output_flags |= OUTPUT_FLAG__ALERTS;
    Snort::set_main_hook(DetectionEngine::inspect);
}

void SnortConfig::set_log_mode(const char* val)
{
    if (strcasecmp(val, LOG_NONE) == 0)
    {
        Snort::set_main_hook(snort_ignore);
        EventManager::enable_logs(false);
    }
    else
    {
        if ( !strcmp(val, LOG_DUMP) )
            val = LOG_CODECS;
        output = val;
        Snort::set_main_hook(snort_log);
    }
}

void SnortConfig::enable_syslog()
{
   static bool syslog_configured = false;

    if (syslog_configured)
        return;

    openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);

    logging_flags |= LOGGING_FLAG__SYSLOG;
    syslog_configured = true;
}

void SnortConfig::free_rule_state_list()
{
    RuleState* head = rule_state_list;

    while ( head )
    {
        RuleState* tmp = head;
        head = head->next;
        snort_free(tmp);
    }
    rule_state_list = nullptr;
}

