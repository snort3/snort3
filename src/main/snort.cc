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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort.h"

#include <sys/stat.h>
#include <syslog.h>

#include "actions/ips_actions.h"
#include "codecs/codec_api.h"
#include "connectors/connectors.h"
#include "decompress/file_decomp.h"
#include "detection/context_switcher.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "detection/fp_config.h"
#include "detection/fp_detect.h"
#include "detection/ips_context.h"
#include "detection/tag.h"
#include "file_api/file_service.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfthreshold.h"
#include "flow/ha.h"
#include "framework/endianness.h"
#include "framework/mpse.h"
#include "helpers/base64_encoder.h"
#include "helpers/process.h"
#include "host_tracker/host_cache.h"
#include "ips_options/ips_flowbits.h"
#include "ips_options/ips_options.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "log/log.h"
#include "log/messages.h"
#include "loggers/loggers.h"
#include "main.h"
#include "main/shell.h"
#include "main/thread_config.h"
#include "managers/action_manager.h"
#include "managers/codec_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "managers/mpse_manager.h"
#include "managers/plugin_manager.h"
#include "managers/script_manager.h"
#include "memory/memory_cap.h"
#include "network_inspectors/network_inspectors.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/trough.h"
#include "packet_tracer/packet_tracer.h"
#include "parser/cmd_line.h"
#include "parser/parser.h"
#include "profiler/profiler.h"
#include "search_engines/search_engines.h"
#include "service_inspectors/service_inspectors.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "stream/stream_inspectors.h"
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
#include "piglet_plugins/piglet_plugins.h"
#endif

#ifdef SHELL
#include "control_mgmt.h"
#endif

#include "build.h"
#include "snort_config.h"
#include "thread_config.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------

static SnortConfig* snort_cmd_line_conf = nullptr;
static pid_t snort_main_thread_pid = 0;

// non-local for easy access from core
static THREAD_LOCAL DAQ_PktHdr_t s_pkth;
static THREAD_LOCAL uint8_t* s_data = nullptr;
static THREAD_LOCAL Packet* s_packet = nullptr;
static THREAD_LOCAL ContextSwitcher* s_switcher = nullptr;

ContextSwitcher* Snort::get_switcher()
{ return s_switcher; }

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
    p->user_inspection_policy_id = get_inspection_policy()->user_policy_id;
    p->user_ips_policy_id = get_ips_policy()->user_policy_id;
    p->user_network_policy_id = get_network_policy()->user_policy_id;
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

    load_actions();
    load_codecs();
    load_connectors();
    load_ips_options();
    load_loggers();
#ifdef PIGLET
    load_piglets();
#endif
    load_search_engines();
    load_stream_inspectors();
    load_network_inspectors();
    load_service_inspectors();

    /* chew up the command line */
    snort_cmd_line_conf = parse_cmd_line(argc, argv);
    SnortConfig::set_conf(snort_cmd_line_conf);

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

    if ( SnortConfig::get_conf()->logging_flags & LOGGING_FLAG__SHOW_PLUGINS )
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
    SnortConfig::set_conf(sc);

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    CodecManager::instantiate();

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    if ( !SnortConfig::get_conf()->output.empty() )
        EventManager::instantiate(SnortConfig::get_conf()->output.c_str(), SnortConfig::get_conf());

    if (SnortConfig::alert_before_pass())
    {
        OrderRuleLists(SnortConfig::get_conf(), "drop sdrop reject alert pass log");
    }

    SnortConfig::get_conf()->setup();

    FileService::post_init();

    // Must be after CodecManager::instantiate()
    if ( !InspectorManager::configure(SnortConfig::get_conf()) )
        ParseError("can't initialize inspectors");
    else if ( SnortConfig::log_verbose() )
        InspectorManager::print_config(SnortConfig::get_conf());

    ModuleManager::reset_stats(SnortConfig::get_conf());

    if (SnortConfig::get_conf()->file_mask != 0)
        umask(SnortConfig::get_conf()->file_mask);
    else
        umask(077);    /* set default to be sane */

    /* Need to do this after dynamic detection stuff is initialized, too */
    IpsManager::global_init(SnortConfig::get_conf());

    SnortConfig::get_conf()->post_setup();

    MpseManager::activate_search_engine(
        SnortConfig::get_conf()->fast_pattern_config->get_search_api(), SnortConfig::get_conf());

    SFAT_Start();

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    /* Finish up the pcap list and put in the queues */
    Trough::setup();

    // FIXIT-L refactor stuff done here and in snort_config.cc::VerifyReload()
    if ( SnortConfig::get_conf()->bpf_filter.empty() && !SnortConfig::get_conf()->bpf_file.empty() )
        SnortConfig::get_conf()->bpf_filter = read_infile("bpf_file", SnortConfig::get_conf()->bpf_file.c_str());

    if ( !SnortConfig::get_conf()->bpf_filter.empty() )
        LogMessage("Snort BPF option: %s\n", SnortConfig::get_conf()->bpf_filter.c_str());

    parser_term(SnortConfig::get_conf());
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

bool Snort::drop_privileges()
{
    /* Enter the chroot jail if necessary. */
    if (!SnortConfig::get_conf()->chroot_dir.empty() &&
        !EnterChroot(SnortConfig::get_conf()->chroot_dir, SnortConfig::get_conf()->log_dir))
        return false;

    /* Drop privileges if requested. */
    if (SnortConfig::get_uid() != -1 || SnortConfig::get_gid() != -1)
    {
        if (!SFDAQ::unprivileged())
        {
            ParseError("Cannot drop privileges - %s DAQ does not support unprivileged operation.\n",
                    SFDAQ::get_type());
            return false;
        }
        if (!SetUidGid(SnortConfig::get_uid(), SnortConfig::get_gid()))
            return false;
    }

    initializing = false;
    privileges_dropped = true;

    return true;
}

void Snort::do_pidfile()
{
    static bool pid_file_created = false;

    if (SnortConfig::create_pid_file() && !pid_file_created)
    {
        CreatePidFile(snort_main_thread_pid);
        pid_file_created = true;
    }
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
    IpsManager::global_term(SnortConfig::get_conf());
    SFAT_Cleanup();
    host_cache.clear();

#ifdef PIGLET
    if ( !Piglet::piglet_mode() )
#endif
    Trough::cleanup();

    ClosePidFile();

    /* remove pid file */
    if ( !SnortConfig::get_conf()->pid_filename.empty() )
    {
        int ret = unlink(SnortConfig::get_conf()->pid_filename.c_str());

        if (ret != 0)
        {
            ErrorMessage("Could not remove pid file %s: %s\n",
                SnortConfig::get_conf()->pid_filename.c_str(), get_error(errno));
        }
    }

    //MpseManager::print_search_engine_stats();

    FileService::close();

    sfthreshold_free();  // FIXDAQ etc.
    RateFilter_Cleanup();

    Periodic::unregister_all();

    LogMessage("%s  Snort exiting\n", get_prompt());

    /* free allocated memory */
    if (SnortConfig::get_conf() == snort_cmd_line_conf)
    {
        delete snort_cmd_line_conf;
        snort_cmd_line_conf = nullptr;
        SnortConfig::set_conf(nullptr);
    }
    else
    {
        delete snort_cmd_line_conf;
        snort_cmd_line_conf = nullptr;

        delete SnortConfig::get_conf();
        SnortConfig::set_conf(nullptr);
    }

    CleanupProtoNames();
    SideChannelManager::term();
    ModuleManager::term();
    PluginManager::release_plugins();
    ScriptManager::release_scripts();
}

void Snort::clean_exit(int)
{
    term();
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

Packet* Snort::get_packet()
{ return s_packet; }

void Snort::setup(int argc, char* argv[])
{
    set_main_thread();

    // must be done before any other files are opened because we
    // will try to grab file descriptor 3 (if --enable-stdlog)
    OpenLogger();

    init(argc, argv);

    LogMessage("%s\n", LOG_DIV);
    SFDAQ::init(SnortConfig::get_conf());

    if ( SnortConfig::daemon_mode() )
        daemonize();

    // this must follow daemonization
    snort_main_thread_pid = gettid();

    /* Change groups */
    InitGroups(SnortConfig::get_uid(), SnortConfig::get_gid());

    set_quick_exit(false);

    memory::MemoryCap::calculate(ThreadConfig::get_instance_max());
    memory::MemoryCap::print();

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
    reset_parse_errors();
    trim_heap();

    parser_init();
    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf, fname);
    sc->merge(snort_cmd_line_conf);

    if ( ModuleManager::get_errors() || !sc->verify() )
    {
        parser_term(sc);
        delete sc;
        reloading = false;
        return nullptr;
    }

    sc->setup();

#ifdef SHELL
    ControlMgmt::reconfigure_controls();
#endif

    if ( get_parse_errors() or !InspectorManager::configure(sc) )
    {
        parser_term(sc);
        delete sc;
        reloading = false;
        return nullptr;
    }

    FlowbitResetCounts();  // FIXIT-L updates global hash, put in sc

    if ((sc->file_mask != 0) && (sc->file_mask != SnortConfig::get_conf()->file_mask))
        umask(sc->file_mask);

    // FIXIT-L is this still needed?
    /* Transfer any user defined rule type outputs to the new rule list */
    {
        RuleListNode* cur = SnortConfig::get_conf()->rule_lists;

        for (; cur != nullptr; cur = cur->next)
        {
            RuleListNode* rnew = sc->rule_lists;

            for (; rnew != nullptr; rnew = rnew->next)
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

    sc->post_setup();

    if ( sc->fast_pattern_config->get_search_api() !=
        SnortConfig::get_conf()->fast_pattern_config->get_search_api() )
    {
        MpseManager::activate_search_engine(sc->fast_pattern_config->get_search_api(), sc);
    }

    reloading = false;
    parser_term(sc);

    return sc;
}

SnortConfig* Snort::get_updated_policy(SnortConfig* other_conf, const char* fname, const char* iname)
{
    reloading = true;

    SnortConfig* sc = new SnortConfig(other_conf);

    if ( fname )
    {
        Shell sh = Shell(fname);
        sh.configure(sc);

        if ( ModuleManager::get_errors() || !sc->verify() )
        {
            sc->cloned = true;
            InspectorManager::update_policy(other_conf);
            delete sc;
            set_default_policy(other_conf);
            reloading = false;
            return nullptr;
        }
    }

    if ( iname )
    {
        if ( !InspectorManager::delete_inspector(sc, iname) )
        {
            sc->cloned = true;
            InspectorManager::update_policy(other_conf);
            delete sc;
            set_default_policy(other_conf);
            reloading = false;
            return nullptr;
        }
    }

    if ( !InspectorManager::configure(sc, true) )
    {
        sc->cloned = true;
        InspectorManager::update_policy(other_conf);
        delete sc;
        set_default_policy(other_conf);
        reloading = false;
        return nullptr;
    }

    other_conf->cloned = true;

    InspectorManager::update_policy(sc);
    reloading = false;
    return sc;
}

SnortConfig* Snort::get_updated_module(SnortConfig* other_conf, const char* name)
{
    reloading = true;

    SnortConfig* sc = new SnortConfig(other_conf);

    if ( name )
    {
        ModuleManager::reload_module(name, sc);
        if ( ModuleManager::get_errors() || !sc->verify() )
        {
            sc->cloned = true;
            InspectorManager::update_policy(other_conf);
            delete sc;
            set_default_policy(other_conf);
            reloading = false;
            return nullptr;
        }
    }

    if ( !InspectorManager::configure(sc, true) )
    {
        sc->cloned = true;
        InspectorManager::update_policy(other_conf);
        delete sc;
        set_default_policy(other_conf);
        reloading = false;
        return nullptr;
    }

    other_conf->cloned = true;

    InspectorManager::update_policy(sc);
    reloading = false;
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
    // FIXIT-L this whole thing could be pub-sub
    DataBus::publish(THREAD_IDLE_EVENT, nullptr);
    Stream::timeout_flows(time(nullptr));
    aux_counts.idle++;
    HighAvailabilityManager::process_receive();
}

void Snort::thread_rotate()
{
    DataBus::publish(THREAD_ROTATE_EVENT, nullptr);
}

/*
 * Perform all packet thread initialization actions that need to be taken with escalated privileges
 * prior to starting the DAQ module.
 */
bool Snort::thread_init_privileged(const char* intf)
{
    s_data = new uint8_t[65535];
    show_source(intf);

    SnortConfig::get_conf()->thread_config->implement_thread_affinity(STHREAD_TYPE_PACKET, get_instance_id());

    // FIXIT-M the start-up sequence is a little off due to dropping privs
    SFDAQInstance *daq_instance = new SFDAQInstance(intf);
    SFDAQ::set_local_instance(daq_instance);
    if (!daq_instance->configure(SnortConfig::get_conf()))
    {
        SFDAQ::set_local_instance(nullptr);
        delete daq_instance;
        return false;
    }

    return true;
}

/*
 * Perform all packet thread initialization actions that can be taken with dropped privileges
 * and/or must be called after the DAQ module has been started.
 */
void Snort::thread_init_unprivileged()
{
    // using dummy values until further integration
    const unsigned max_contexts = 20;

    s_switcher = new ContextSwitcher(max_contexts);

    for ( unsigned i = 0; i < max_contexts; ++i )
        s_switcher->push(new IpsContext);

    CodecManager::thread_init(SnortConfig::get_conf());

    // this depends on instantiated daq capabilities
    // so it is done here instead of init()
    Active::init(SnortConfig::get_conf());

    InitTag();
    EventTrace_Init();
    detection_filter_init(SnortConfig::get_conf()->detection_filter_config);
    DetectionEngine::thread_init();

    EventManager::open_outputs();
    IpsManager::setup_options();
    ActionManager::thread_init(SnortConfig::get_conf());
    FileService::thread_init();
    SideChannelManager::thread_init();
    HighAvailabilityManager::thread_init(); // must be before InspectorManager::thread_init();
    InspectorManager::thread_init(SnortConfig::get_conf());
    PacketTracer::thread_init();
    
    // in case there are HA messages waiting, process them first
    HighAvailabilityManager::process_receive();
    PacketManager::thread_init();
}

void Snort::thread_term()
{
    HighAvailabilityManager::thread_term_beginning();

    if ( !SnortConfig::get_conf()->dirty_pig )
        Stream::purge_flows();

    DetectionEngine::idle();
    InspectorManager::thread_stop(SnortConfig::get_conf());
    ModuleManager::accumulate(SnortConfig::get_conf());
    InspectorManager::thread_term(SnortConfig::get_conf());
    ActionManager::thread_term(SnortConfig::get_conf());

    IpsManager::clear_options();
    EventManager::close_outputs();
    CodecManager::thread_term();
    HighAvailabilityManager::thread_term();
    SideChannelManager::thread_term();

    s_packet = nullptr;

    SFDAQInstance *daq_instance = SFDAQ::get_local_instance();
    if ( daq_instance->was_started() )
        daq_instance->stop();
    SFDAQ::set_local_instance(nullptr);
    delete daq_instance;

    PacketLatency::tterm();
    RuleLatency::tterm();

    Profiler::consolidate_stats();

    DetectionEngine::thread_term();
    detection_filter_term();
    EventTrace_Term();
    CleanupTag();
    FileService::thread_term();
    PacketTracer::thread_term();
    PacketManager::thread_term();

    Active::term();
    delete s_switcher;
    delete[] s_data;
}

void Snort::inspect(Packet* p)
{
    // Need to include this b/c call is outside the detect tree
    Profile detect_profile(detectPerfStats);
    Profile rebuilt_profile(rebuiltPacketPerfStats);

    DetectionEngine de;
    main_hook(p);
}

DAQ_Verdict Snort::process_packet(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt, bool is_frag)
{
    aux_counts.rx_bytes += pkthdr->caplen;

    PacketManager::decode(p, pkthdr, pkt, is_frag);
    assert(p->pkth && p->pkt);

    PacketTracer::activate(*p);

    if (is_frag)
    {
        p->packet_flags |= (PKT_PSEUDO | PKT_REBUILT_FRAG);
        p->pseudo_type = PSEUDO_PKT_IP;
    }

    set_policy(p);  // FIXIT-M should not need this here

    if ( !(p->packet_flags & PKT_IGNORE) )
    {
        clear_file_data();
        main_hook(p);

        // FIXIT-L remove this onload when DAQng can push multiple packets
        if ( p->flow )
            DetectionEngine::onload(p->flow);
    }

    // process flow verdicts here
    if ( Active::packet_retry_requested() )
    {
        return DAQ_VERDICT_RETRY;
    }
    else if ( Active::session_was_blocked() )
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
static DAQ_Verdict update_verdict(Packet* p, DAQ_Verdict verdict, int& inject)
{
    if ( Active::packet_was_dropped() and Active::can_block() )
    {
        if ( verdict == DAQ_VERDICT_PASS )
            verdict = DAQ_VERDICT_BLOCK;
    }
    else if ( p->packet_flags & PKT_RESIZED )
    {
        // we never increase, only trim, but daq doesn't support resizing wire packet
        PacketManager::encode_update(p);

        if ( !SFDAQ::inject(p->pkth, 0, p->pkt, p->pkth->pktlen) )
        {
            inject = 1;
            verdict = DAQ_VERDICT_BLOCK;
        }
    }
    else if ( p->packet_flags & PKT_MODIFIED )
    {
        // this packet was normalized and/or has replacements
        PacketManager::encode_update(p);
        verdict = DAQ_VERDICT_REPLACE;
    }
    else if ( (p->packet_flags & PKT_IGNORE) ||
        (p->flow && p->flow->get_ignore_direction( ) == SSN_DIR_BOTH) )
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
    else if ( p->ptrs.decode_flags & DECODE_PKT_TRUST )
    {
        if (p->flow)
            p->flow->set_ignore_direction(SSN_DIR_BOTH);
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
    packet_time_update(&pkthdr->ts);

    if ( SnortConfig::get_conf()->pkt_skip && pc.total_from_daq <= SnortConfig::get_conf()->pkt_skip )
        return DAQ_VERDICT_PASS;

    s_switcher->start();
    s_packet = s_switcher->get_context()->packet;
    s_packet->context->packet_number = pc.total_from_daq;

    DetectionEngine::reset();

    sfthreshold_reset();
    ActionManager::reset_queue();

    DAQ_Verdict verdict = process_packet(s_packet, pkthdr, pkt);
    ActionManager::execute(s_packet);

    int inject = 0;
    verdict = update_verdict(s_packet, verdict, inject);

    if (PacketTracer::is_active())
    {
        PacketTracer::log("Policies: Network %u, Inspection %u, Detection %u\n",
            get_network_policy()->user_policy_id, get_inspection_policy()->user_policy_id,
            get_ips_policy()->user_policy_id);
        PacketTracer::log("Verdict: %s\n", SFDAQ::verdict_to_string(verdict));

        PacketTracer::dump(pkthdr);
    }

    HighAvailabilityManager::process_update(s_packet->flow, pkthdr);

    Active::reset();
    Stream::timeout_flows(pkthdr->ts.tv_sec);
    HighAvailabilityManager::process_receive();

    s_packet->pkth = nullptr;  // no longer avail upon sig segv

    if ( SnortConfig::get_conf()->pkt_cnt && pc.total_from_daq >= SnortConfig::get_conf()->pkt_cnt )
        SFDAQ::break_loop(-1);

    else if ( break_time() )
        SFDAQ::break_loop(0);

    s_switcher->stop();

    return verdict;
}

