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

#include "snort.h"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/stat.h>

#include "decompress/file_decomp.h"
#include "detection/detect.h"
#include "detection/detection_util.h"
#include "detection/fp_config.h"
#include "detection/fp_detect.h"
#include "detection/tag.h"
#include "file_api/file_service.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfthreshold.h"
#include "flow/ha.h"
#include "framework/mpse.h"
#include "helpers/process.h"
#include "host_tracker/host_cache.h"
#include "ips_options/ips_flowbits.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "log/messages.h"
#include "managers/action_manager.h"
#include "managers/codec_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "managers/mpse_manager.h"
#include "managers/plugin_manager.h"
#include "managers/script_manager.h"
#include "packet_io/sfdaq.h"
#include "packet_io/active.h"
#include "packet_io/trough.h"
#include "parser/cmd_line.h"
#include "parser/parser.h"
#include "perf_monitor/perf_monitor.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "target_based/sftarget_reader.h"
#include "time/packet_time.h"
#include "time/periodic.h"
#include "utils/kmap.h"
#include "utils/util.h"
#include "utils/util_utf.h"
#include "utils/util_jsnorm.h"

#ifdef PIGLET
#include "piglet/piglet.h"
#include "piglet/piglet_manager.h"
#endif

#include "build.h"
#include "main.h"
#include "snort_config.h"
#include "snort_debug.h"
#include "thread_config.h"

using namespace std;

//-------------------------------------------------------------------------

static SnortConfig* snort_cmd_line_conf = nullptr;
static pid_t snort_main_thread_pid = 0;

// non-local for easy access from core
static THREAD_LOCAL DAQ_PktHdr_t s_pkth;
static THREAD_LOCAL uint8_t s_data[65536];
static THREAD_LOCAL Packet* s_packet = nullptr;

//-------------------------------------------------------------------------
// perf stats
// FIXIT-M move these to appropriate modules
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats totalPerfStats;
static THREAD_LOCAL ProfileStats metaPerfStats;

static ProfileStats* get_profile(const char* key)
{
    if ( !strcmp(key, "detect") )
        return &detectPerfStats;

    if ( !strcmp(key, "mpse") )
        return &mpsePerfStats;

    if ( !strcmp(key, "rebuilt_packet") )
        return &rebuiltPacketPerfStats;

    if ( !strcmp(key, "rule_eval") )
        return &rulePerfStats;

    if ( !strcmp(key, "rtn_eval") )
        return &ruleRTNEvalPerfStats;

    if ( !strcmp(key, "rule_tree_eval") )
        return &ruleOTNEvalPerfStats;

    if ( !strcmp(key, "nfp_rule_tree_eval") )
        return &ruleNFPEvalPerfStats;

    if ( !strcmp(key, "decode") )
        return &decodePerfStats;

    if ( !strcmp(key, "eventq") )
        return &eventqPerfStats;

    if ( !strcmp(key, "total") )
        return &totalPerfStats;

    if ( !strcmp(key, "daq_meta") )
        return &metaPerfStats;

    return nullptr;
}

static void register_profiles()
{
    Profiler::register_module("detect", nullptr, get_profile);
    Profiler::register_module("mpse", "detect", get_profile);
    Profiler::register_module("rebuilt_packet", "detect", get_profile);
    Profiler::register_module("rule_eval", "detect", get_profile);
    Profiler::register_module("rtn_eval", "rule_eval", get_profile);
    Profiler::register_module("rule_tree_eval", "rule_eval", get_profile);
    Profiler::register_module("nfp_rule_tree_eval", "rule_eval", get_profile);
    Profiler::register_module("decode", nullptr, get_profile);
    Profiler::register_module("eventq", nullptr, get_profile);
    Profiler::register_module("total", nullptr, get_profile);
    Profiler::register_module("daq_meta", nullptr, get_profile);
}

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static void pass_pkts(Packet*) { }
static MainHook_f main_hook = pass_pkts;

static void set_policy(Packet* p)  // FIXIT-M delete this?
{
    set_default_policy();
    p->user_policy_id = get_ips_policy()->user_policy_id;
}

static void show_source(const char* pcap)
{
    if ( !SnortConfig::pcap_show() )
        return;

    if ( !strcmp(pcap, "-") )
        pcap = "stdin";

    static bool first = true;
    if ( first )
        first = false;
    else
        fprintf(stdout, "%s", "\n");

    fprintf(stdout, "Reading network traffic from \"%s\" with snaplen = %u\n",
        pcap, SFDAQ::get_snap_len());
}

//-------------------------------------------------------------------------
// initialization
//-------------------------------------------------------------------------

void Snort::init(int argc, char** argv)
{
    init_signals();
    ThreadConfig::init();

#if defined(NOCOREFILE)
    SetNoCores();
#else
    StoreSnortInfoStrings();
#endif

    InitProtoNames();
    SFAT_Init();

    /* chew up the command line */
    snort_cmd_line_conf = parse_cmd_line(argc, argv);
    snort_conf = snort_cmd_line_conf;

    LogMessage("--------------------------------------------------\n");
    LogMessage("%s  Snort++ %s-%s\n", get_prompt(), VERSION, BUILD);
    LogMessage("--------------------------------------------------\n");

#ifdef PIGLET
    Piglet::Manager::init();
#endif

    SideChannelManager::pre_config_init();
    HighAvailabilityManager::pre_config_init();

    ModuleManager::init();
    ScriptManager::load_scripts(snort_cmd_line_conf->script_paths);
    PluginManager::load_plugins(snort_cmd_line_conf->plugin_path);

    if ( snort_conf->logging_flags & LOGGING_FLAG__SHOW_PLUGINS )
    {
        ModuleManager::dump_modules();
        PluginManager::dump_plugins();
    }

    FileService::init();
    register_profiles();

    parser_init();
    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf);

    /* Merge the command line and config file confs to take care of
     * command line overriding config file.
     * Set the global snort_conf that will be used during run time */
    sc->merge(snort_cmd_line_conf);
    snort_conf = sc;

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    CodecManager::instantiate();

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    if ( !snort_conf->output.empty() )
        EventManager::instantiate(snort_conf->output.c_str(), snort_conf);

    if (SnortConfig::alert_before_pass())
    {
        OrderRuleLists(snort_conf, "drop sdrop reject alert pass log");
    }

    snort_conf->setup();

    FileService::post_init();

    // Must be after CodecManager::instantiate()
    if ( !InspectorManager::configure(snort_conf) )
        ParseError("can't initialize inspectors");

    else if ( SnortConfig::log_verbose() )
        InspectorManager::print_config(snort_conf);

    if (snort_conf->file_mask != 0)
        umask(snort_conf->file_mask);
    else
        umask(077);    /* set default to be sane */

    /* Need to do this after dynamic detection stuff is initialized, too */
    IpsManager::global_init(snort_conf);

    MpseManager::activate_search_engine(
        snort_conf->fast_pattern_config->get_search_api(), snort_conf);

    SFAT_Start();

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    /* Finish up the pcap list and put in the queues */
    Trough::setup();

    // FIXIT-L refactor stuff done here and in snort_config.cc::VerifyReload()
    if ( snort_conf->bpf_filter.empty() && !snort_conf->bpf_file.empty() )
        snort_conf->bpf_filter = read_infile("bpf_file", snort_conf->bpf_file.c_str());

    if ( !snort_conf->bpf_filter.empty() )
        LogMessage("Snort BPF option: %s\n", snort_conf->bpf_filter.c_str());

    parser_term();
}

// this function should only include initialization that must be done as a
// non-root user such as creating log files.  other initialization stuff should
// be in the main initialization function since, depending on platform and
// configuration, this may be running in a background thread while passing
// packets in a fail open mode in the main thread.  we don't want big delays
// here to cause excess latency or dropped packets in that thread which may
// be the case if all threads are pinned to a single cpu/core.
//
// clarification: once snort opens/starts the DAQ, packets are queued for snort
// and must be disposed of quickly or the queue will overflow and packets will
// be dropped so the fail open thread does the remaining initialization while
// the main thread passes packets.  prior to opening and starting the DAQ,
// packet passing is done by the driver/hardware.  the goal then is to put as
// much initialization stuff in Snort::init() as possible and to restrict this
// function to those things that depend on DAQ startup or non-root user/group.

void Snort::drop_privileges()
{
    /* FIXIT-M X - I have no idea if the chroot functionality actually works. */
    /* Drop the Chrooted Settings */
    if ( !snort_conf->chroot_dir.empty() )
        SetChroot(snort_conf->chroot_dir, snort_conf->log_dir);

    /* Drop privileges if requested, when initialization is done */
    SetUidGid(SnortConfig::get_uid(), SnortConfig::get_gid());

    if ( SnortConfig::create_pid_file() )
        CreatePidFile(snort_main_thread_pid);

    initializing = false;
    privileges_dropped = true;
}

//-------------------------------------------------------------------------
// termination
//-------------------------------------------------------------------------

void Snort::term()
{
    /* This function can be called more than once.  For example,
     * once from the SIGINT signal handler, and once recursively
     * as a result of calling pcap_close() below.  We only need
     * to perform the cleanup once, however.  So the static
     * variable already_exiting will act as a flag to prevent
     * double-freeing any memory.  Not guaranteed to be
     * thread-safe, but it will prevent the simple cases.
     */
    static bool already_exiting = false;
    if ( already_exiting )
        return;

    already_exiting = true;
    initializing = false;  // just in case we cut out early

    term_signals();
    IpsManager::global_term(snort_conf);
    SFAT_Cleanup();
    host_cache.clear();

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    Trough::cleanup();

    ClosePidFile();

    /* remove pid file */
    if ( !snort_conf->pid_filename.empty() )
    {
        int ret = unlink(snort_conf->pid_filename.c_str());

        if (ret != 0)
        {
            ErrorMessage("Could not remove pid file %s: %s\n",
                snort_conf->pid_filename.c_str(), get_error(errno));
        }
    }

    //MpseManager::print_search_engine_stats();

    FileService::close();

    sfthreshold_free();  // FIXDAQ etc.
    RateFilter_Cleanup();

    Periodic::unregister_all();

    /* free allocated memory */
    if (snort_conf == snort_cmd_line_conf)
    {
        delete snort_cmd_line_conf;
        snort_cmd_line_conf = NULL;
        snort_conf = NULL;
    }
    else
    {
        delete snort_cmd_line_conf;
        snort_cmd_line_conf = NULL;

        delete snort_conf;
        snort_conf = NULL;
    }
    CleanupProtoNames();
    SideChannelManager::term();
    ModuleManager::term();
    PluginManager::release_plugins();
    ScriptManager::release_scripts();
}

void Snort::clean_exit(int)
{
    SnortConfig tmp;

    // Have to trick LogMessage to log correctly after snort_conf is freed
    if ( snort_conf )
    {
        tmp.logging_flags |=
            (snort_conf->logging_flags & LOGGING_FLAG__QUIET);

        tmp.run_flags |= (snort_conf->run_flags & RUN_FLAG__DAEMON);

        tmp.logging_flags |=
            (snort_conf->logging_flags & LOGGING_FLAG__SYSLOG);
    }

    term();
    snort_conf = &tmp;

    LogMessage("%s  Snort exiting\n", get_prompt());
    closelog();
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

bool Snort::initializing = true;
bool Snort::reloading = false;
bool Snort::privileges_dropped = false;

bool Snort::is_starting()
{ return initializing; }

bool Snort::is_reloading()
{ return reloading; }

bool Snort::has_dropped_privileges()
{ return privileges_dropped; }

void Snort::set_main_hook(MainHook_f f)
{ main_hook = f; }

void Snort::setup(int argc, char* argv[])
{
    set_main_thread();

    OpenLogger();

    init(argc, argv);

    LogMessage("%s\n", LOG_DIV);
    SFDAQ::init(snort_conf);

    if ( SnortConfig::daemon_mode() )
        daemonize();

    // this must follow daemonization
    snort_main_thread_pid = gettid();

    /* Change groups */
    InitGroups(SnortConfig::get_uid(), SnortConfig::get_gid());

    set_quick_exit(false);

    keep_utf_lib();
    keep_kmap_lib();
    keep_decomp_lib();
    keep_jsnorm_lib();

    TimeStart();
}

void Snort::cleanup()
{
    TimeStop();

    SFDAQ::term();

    if ( !SnortConfig::test_mode() )  // FIXIT-M ideally the check is in one place
        PrintStatistics();

    CloseLogger();
    ThreadConfig::term();
    clean_exit(0);
}

// FIXIT-M refactor this so startup and reload call the same core function to
// instantiate things that can be reloaded
SnortConfig* Snort::get_reload_config(const char* fname)
{
    reloading = true;
    ModuleManager::reset_errors();
    trim_heap();

    parser_init();
    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf, fname);
    sc->merge(snort_cmd_line_conf);

    if ( ModuleManager::get_errors() || !sc->verify() )
    {
        delete sc;
        reloading = false;
        parser_term();
        return NULL;
    }

    sc->setup();

    if ( !InspectorManager::configure(sc) )
    {
        delete sc;
        reloading = false;
        parser_term();
        return NULL;
    }

    FlowbitResetCounts();  // FIXIT-L updates global hash, put in sc

    if ((sc->file_mask != 0) && (sc->file_mask != snort_conf->file_mask))
        umask(sc->file_mask);

    // FIXIT-L is this still needed?
    /* Transfer any user defined rule type outputs to the new rule list */
    {
        RuleListNode* cur = snort_conf->rule_lists;

        for (; cur != NULL; cur = cur->next)
        {
            RuleListNode* rnew = sc->rule_lists;

            for (; rnew != NULL; rnew = rnew->next)
            {
                if (strcasecmp(cur->name, rnew->name) == 0)
                {
                    EventManager::copy_outputs(
                        rnew->RuleList->AlertList, cur->RuleList->AlertList);

                    EventManager::copy_outputs(
                        rnew->RuleList->LogList, cur->RuleList->LogList);
                    break;
                }
            }
        }
    }

    if ( sc->fast_pattern_config->get_search_api() !=
        snort_conf->fast_pattern_config->get_search_api() )
    {
        MpseManager::activate_search_engine(sc->fast_pattern_config->get_search_api(), sc);
    }

    reloading = false;
    parser_term();

    return sc;
}

void Snort::capture_packet()
{
    if ( snort_main_thread_pid == gettid() )
    {
        // FIXIT-L main thread crashed.  Do anything?
    }
    else
    {
        // Copy the crashed threads data.  C++11 specs ensure the
        // thread that segfaulted will still be running.
        if ( s_packet && s_packet->pkth )
        {
            s_pkth = *(s_packet->pkth);

            if ( s_packet->pkt )
            {
                memcpy(s_data, s_packet->pkt, 0xFFFF & s_packet->pkth->caplen);
                s_packet->pkt = s_data;
            }
        }
    }
}

void Snort::thread_idle()
{
    Stream::timeout_flows(time(nullptr));
    perf_monitor_idle_process();
    aux_counts.idle++;
    HighAvailabilityManager::process_receive();
}

void Snort::thread_rotate()
{
    SetRotatePerfFileFlag();
}

/*
 * Perform all packet thread initialization actions that need to be taken with escalated privileges
 * prior to starting the DAQ module.
 */
bool Snort::thread_init_privileged(const char* intf)
{
    show_source(intf);

    snort_conf->thread_config->implement_thread_affinity(STHREAD_TYPE_PACKET, get_instance_id());

    // FIXIT-M the start-up sequence is a little off due to dropping privs
    SFDAQInstance *daq_instance = new SFDAQInstance(intf);
    SFDAQ::set_local_instance(daq_instance);
    if (!daq_instance->configure(snort_conf))
        return false;

    return true;
}

/*
 * Perform all packet thread initialization actions that can be taken with dropped privileges
 * and/or must be called after the DAQ module has been started.
 */
void Snort::thread_init_unprivileged()
{
    s_packet = new Packet(false);
    CodecManager::thread_init(snort_conf);

    // this depends on instantiated daq capabilities
    // so it is done here instead of init()
    Active::init(snort_conf);

    SnortEventqNew(snort_conf->event_queue_config);

    InitTag();

    EventTrace_Init();
    detection_filter_init(snort_conf->detection_filter_config);

    otnx_match_data_init(snort_conf->num_rule_types);

    EventManager::open_outputs();
    IpsManager::setup_options();
    ActionManager::thread_init(snort_conf);
    FileService::thread_init();
    SideChannelManager::thread_init();
    HighAvailabilityManager::thread_init(); // must be before InspectorManager::thread_init();
    InspectorManager::thread_init(snort_conf);

    // in case there are HA messages waiting, process them first
    HighAvailabilityManager::process_receive();
}

void Snort::thread_term()
{
    HighAvailabilityManager::thread_term_beginning();

    if ( !snort_conf->dirty_pig )
        Stream::purge_flows();

    InspectorManager::thread_stop(snort_conf);
    ModuleManager::accumulate(snort_conf);
    InspectorManager::thread_term(snort_conf);
    ActionManager::thread_term(snort_conf);

    IpsManager::clear_options();
    EventManager::close_outputs();
    CodecManager::thread_term();
    HighAvailabilityManager::thread_term();
    SideChannelManager::thread_term();

    if ( s_packet )
    {
        delete s_packet;
        s_packet = nullptr;
    }

    SFDAQInstance *daq_instance = SFDAQ::get_local_instance();
    if ( daq_instance->was_started() )
        daq_instance->stop();
    SFDAQ::set_local_instance(nullptr);
    delete daq_instance;

    PacketLatency::tterm();
    RuleLatency::tterm();

    Profiler::consolidate_stats();

    otnx_match_data_term();
    detection_filter_term();
    EventTrace_Term();
    CleanupTag();
    FileService::thread_term();

    SnortEventqFree();
    Active::term();
}

void Snort::detect_rebuilt_packet(Packet* p)
{
    // Need to include this b/c call is outside the detect tree
    Profile detect_profile(detectPerfStats);
    Profile rebuilt_profile(rebuiltPacketPerfStats);

    auto save_do_detect = do_detect;
    auto save_do_detect_content = do_detect_content;

    SnortEventqPush();
    main_hook(p);
    SnortEventqPop();

    DetectReset();

    do_detect = save_do_detect;
    do_detect_content = save_do_detect_content;
}

DAQ_Verdict Snort::process_packet(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt, bool is_frag)
{
    PacketManager::decode(p, pkthdr, pkt);
    assert(p->pkth && p->pkt);

    if (is_frag)
    {
        p->packet_flags |= (PKT_PSEUDO | PKT_REBUILT_FRAG);
        p->pseudo_type = PSEUDO_PKT_IP;
    }

    set_policy(p);  // FIXIT-M should not need this here

    /* just throw away the packet if we are configured to ignore this port */
    if ( !(p->packet_flags & PKT_IGNORE) )
    {
        DetectReset();
        main_hook(p);
    }

    // process flow verdicts here
    if ( Active::session_was_blocked() )
    {
        if ( !Active::can_block() )
            return DAQ_VERDICT_PASS;

        if ( Active::get_tunnel_bypass() )
        {
            aux_counts.internal_blacklist++;
            return DAQ_VERDICT_PASS;
        }

        if ( SnortConfig::inline_mode() || Active::packet_force_dropped() )
            return DAQ_VERDICT_BLACKLIST;
        else
            return DAQ_VERDICT_IGNORE;
    }

    return DAQ_VERDICT_PASS;
}

// process (wire-only) packet verdicts here
static DAQ_Verdict update_verdict(DAQ_Verdict verdict, int& inject)
{
    if ( Active::packet_was_dropped() and Active::can_block() )
    {
        if ( verdict == DAQ_VERDICT_PASS )
            verdict = DAQ_VERDICT_BLOCK;
    }
    else if ( s_packet->packet_flags & PKT_MODIFIED )
    {
        // this packet was normalized and/or has replacements
        PacketManager::encode_update(s_packet);
        verdict = DAQ_VERDICT_REPLACE;
    }
    else if ( s_packet->packet_flags & PKT_RESIZED )
    {
        // we never increase, only trim, but
        // daq doesn't support resizing wire packet
        if ( !SFDAQ::inject(s_packet->pkth, 0, s_packet->pkt, s_packet->pkth->pktlen) )
        {
            inject = 1;
            verdict = DAQ_VERDICT_BLOCK;
        }
    }
    else if ( (s_packet->packet_flags & PKT_IGNORE) ||
        (s_packet->flow && s_packet->flow->get_ignore_direction( ) == SSN_DIR_BOTH) )
    {
        if ( !Active::get_tunnel_bypass() )
        {
            verdict = DAQ_VERDICT_WHITELIST;
        }
        else
        {
            verdict = DAQ_VERDICT_PASS;
            aux_counts.internal_whitelist++;
        }
    }
    else if ( s_packet->ptrs.decode_flags & DECODE_PKT_TRUST )
    {
        if (s_packet->flow)
            s_packet->flow->set_ignore_direction(SSN_DIR_BOTH);
        verdict = DAQ_VERDICT_WHITELIST;
    }
    else
    {
        verdict = DAQ_VERDICT_PASS;
    }
    return verdict;
}

DAQ_Verdict Snort::packet_callback(
    void*, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    set_default_policy();
    Profile profile(totalPerfStats);

    pc.total_from_daq++;
    rule_eval_pkt_count++;
    packet_time_update(&pkthdr->ts);

    if ( snort_conf->pkt_skip && pc.total_from_daq <= snort_conf->pkt_skip )
        return DAQ_VERDICT_PASS;

    {
        Profile eventq_profile(eventqPerfStats);
        SnortEventqReset();
    }

    sfthreshold_reset();
    ActionManager::reset_queue();

    DAQ_Verdict verdict = process_packet(s_packet, pkthdr, pkt);
    ActionManager::execute(s_packet);

    int inject = 0;
    verdict = update_verdict(verdict, inject);

    // FIXIT-H move this to the appropriate struct
    //perfBase->UpdateWireStats(pkthdr->caplen, Active::packet_was_dropped(), inject);
    HighAvailabilityManager::process_update(s_packet->flow, pkthdr);

    Active::reset();
    PacketManager::encode_reset();
    Stream::timeout_flows(pkthdr->ts.tv_sec);
    HighAvailabilityManager::process_receive();

    s_packet->pkth = nullptr;  // no longer avail upon sig segv

    if ( snort_conf->pkt_cnt && pc.total_from_daq >= snort_conf->pkt_cnt )
        SFDAQ::break_loop(-1);

    else if ( break_time() )
        SFDAQ::break_loop(0);

    return verdict;
}

