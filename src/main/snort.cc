//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include <daq.h>
#include <openssl/crypto.h>
#include <sys/stat.h>

#include <cmath>
#include <forward_list>

#include "detection/detection_engine.h"
#include "detection/fp_config.h"
#include "detection/ips_context_data.h"
#include "file_api/file_service.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/sfthreshold.h"
#include "flow/ha.h"
#include "framework/mpse.h"
#include "host_tracker/host_cache.h"
#include "host_tracker/host_cache_segmented.h"
#include "host_tracker/host_tracker_module.h"
#include "log/log.h"
#include "log/log_errors.h"
#include "main.h"
#include "main/modules.h"
#include "main/process.h"
#include "main/shell.h"
#include "managers/codec_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "managers/mp_transport_manager.h"
#include "managers/mpse_manager.h"
#include "managers/plugin_manager.h"
#include "managers/policy_selector_manager.h"
#include "managers/script_manager.h"
#include "managers/so_manager.h"
#include "memory/memory_cap.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/trough.h"
#include "parser/cmd_line.h"
#include "parser/config_file.h"
#include "parser/parser.h"
#include "profiler/profiler.h"
#include "profiler/profiler_impl.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "target_based/host_attributes.h"
#include "time/periodic.h"
#include "trace/trace_api.h"
#include "trace/trace_config.h"
#include "tracer/trace_loader.h"
#include "mp_transport/mp_transports.h"
#include "utils/stats.h"
#include "utils/util.h"

#ifdef SHELL
#include "control/control_mgmt.h"
#include "ac_shell_cmd.h"
#endif

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#include "snort_config.h"
#include "thread_config.h"

using namespace snort;
using namespace std;

static SnortConfig* snort_cmd_line_conf = nullptr;
static pid_t snort_main_thread_pid = 0;

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
    DataBus::init();
    PluginManager::init();
    DetectionEngine::init();

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);

    snort_cmd_line_conf = parse_cmd_line(argc, argv);
    SnortConfig::set_conf(snort_cmd_line_conf);

    init_process_id();

    LogMessage("--------------------------------------------------\n");
#ifdef BUILD
    LogMessage("%s  Snort++ %s-%s\n", get_prompt(), VERSION, BUILD);
#else
    LogMessage("%s  Snort++ %s\n", get_prompt(), VERSION);
#endif
    LogMessage("--------------------------------------------------\n");

    SideChannelManager::pre_config_init();

    PluginManager::load_plugins(snort_cmd_line_conf->plugin_path);
    ScriptManager::load_scripts(snort_cmd_line_conf->script_paths);

    InspectorManager::load_buffer_map();
    InspectorManager::new_map();
    ModuleManager::load_params();
    TraceApi::global_init();

    FileService::init();

    parser_init();
    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf, get_snort_conf());

    /* Set the global snort_conf that will be used during run time */
    SnortConfig::set_conf(sc);
    TraceApi::capture_outputs(sc);

    if (!sc->policy_map->setup_network_policies())
        ParseError("Network policy user ids must be unique\n");

    InspectorManager::prepare_map();

    // This call must be immediately after "SnortConfig::set_conf(sc)"
    // since the first trace call may happen somewhere after this point
    TraceApi::thread_init(sc->trace_config);
    if (sc->max_procs > 1)
    {
        sc->mp_dbus = new MPDataBus();
    }

    PluginManager::capture_plugins(sc);
    Profiler::setup(sc);

    if ( !sc->output.empty() )
        EventManager::instantiate(sc->output.c_str(), sc);

    HighAvailabilityManager::configure(sc->ha_config);
    memory::MemoryCap::init(sc->thread_config->get_instance_max());

    ModuleManager::init_stats();
    ModuleManager::reset_stats(sc);

    if (sc->mp_dbus)
    {
        sc->mp_dbus->init(sc->max_procs);
    }

    if (sc->alert_before_pass())
        sc->rule_order = IpsAction::get_default_priorities(true);

    sc->setup();

    if ( !sc->attribute_hosts_file.empty() )
    {
        if ( !HostAttributesManager::load_hosts_file(sc, sc->attribute_hosts_file.c_str()) )
            ParseError("host attributes file failed to load\n");
    }
    HostAttributesManager::activate(sc);

    if ( SnortConfig::log_verbose() )
        PolicySelectorManager::print_config(sc);

    if ( !InspectorManager::configure(sc) )
        ParseError("can't initialize inspectors");
    else if ( SnortConfig::log_verbose() )
        InspectorManager::print_config(sc);

    InspectorManager::prepare_inspectors(sc);

    // Must be after InspectorManager::configure()
    FileService::post_init();

    if (sc->file_mask != 0)
        umask(sc->file_mask);
    else
        umask(077);    /* set default to be sane */

    /* Need to do this after dynamic detection stuff is initialized, too */
    PacketManager::global_init(sc->num_layers);

    sc->post_setup();

    detection_filter_init(sc->detection_filter_config);

    const MpseApi* search_api = sc->fast_pattern_config->get_search_api();
    const MpseApi* offload_search_api = sc->fast_pattern_config->get_offload_search_api();

    if ( search_api )
        MpseManager::activate_search_engine(search_api, sc);

    if ( offload_search_api and offload_search_api != search_api )
        MpseManager::activate_search_engine(offload_search_api, sc);

    /* Finish up the pcap list and put in the queues */
    Trough::setup();

    // FIXIT-L refactor stuff done here and in snort_config.cc::VerifyReload()
    if ( sc->bpf_filter.empty() && !sc->bpf_file.empty() )
        sc->bpf_filter = read_infile("bpf_file", sc->bpf_file.c_str());

    if ( !sc->bpf_filter.empty() )
        LogMessage("Snort BPF option: %s\n", sc->bpf_filter.c_str());

    parser_term(sc);

    LogMessage("%s\n", LOG_DIV);

    SFDAQ::init(sc->daq_config, ThreadConfig::get_instance_max());
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
    SnortConfig* sc = SnortConfig::get_main_conf();

    // Enter the chroot jail if necessary.
    if (!sc->chroot_dir.empty() && !EnterChroot(sc->chroot_dir, sc->log_dir))
        return false;

    // Drop privileges if requested.
    if (sc->get_uid() != -1 || sc->get_gid() != -1)
    {
        if (!SFDAQ::can_run_unprivileged())
        {
            ParseError("Cannot drop privileges - "
                "at least one of the configured DAQ modules does not support unprivileged operation.\n");
            return false;
        }
        if (!SetUidGid(sc->get_uid(), sc->get_gid()))
            return false;
    }

    privileges_dropped = true;
    return true;
}

void Snort::do_pidfile()
{
    static bool pid_file_created = false;

    if (SnortConfig::get_conf()->create_pid_file() && !pid_file_created)
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
    if ( already_exiting )
        return;
    already_exiting = true;

    const SnortConfig* sc = SnortConfig::get_conf();

    MPTransportManager::term();
    FileService::close();
    call_shutdown_hooks();

    HostAttributesManager::term();

    Trough::cleanup();
    ClosePidFile();

    if ( !sc->pid_filename.empty() )
    {
        int ret = unlink(sc->pid_filename.c_str());

        if (ret != 0)
        {
            ErrorMessage("Could not remove pid file %s: %s\n",
                sc->pid_filename.c_str(), get_error(errno));
        }
    }

    Periodic::unregister_all();

    LogMessage("%s  Snort exiting\n", get_prompt());

    TraceApi::thread_term();
    HighAvailabilityManager::term();
    SideChannelManager::term();
    host_cache.term();
    detection_filter_term();
    CleanupProtoNames();

    // this will actually cause leaks so don't do it
    //OPENSSL_cleanup();

    if (sc != snort_cmd_line_conf)
    {
        PluginManager::revert_plugins(SnortConfig::get_main_conf());
        InspectorManager::tear_down(SnortConfig::get_main_conf());
        delete sc;
    }

    SnortConfig::set_conf(nullptr);

    delete snort_cmd_line_conf;
    snort_cmd_line_conf = nullptr;

    InspectorManager::cleanup();
    memory::MemoryCap::term();
    PluginManager::release_plugins();

    term_signals();
}

void Snort::clean_exit(int)
{
    term();
}

static std::forward_list<void (*)()> shutdown_hooks;

void Snort::add_shutdown_hook(void (*f)())
{ shutdown_hooks.push_front(f); }

void Snort::call_shutdown_hooks()
{
    for (auto f: shutdown_hooks)
        f();

    shutdown_hooks.clear();
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

bool Snort::reloading = false;
bool Snort::privileges_dropped = false;
bool Snort::already_exiting = false;

bool Snort::exit_requested()
{ return ::exit_requested; }

bool Snort::is_reloading()
{ return reloading; }

bool Snort::has_dropped_privileges()
{ return privileges_dropped; }

void Snort::init_process_id()
{
    const SnortConfig* sc = SnortConfig::get_conf();
    if (!sc->id_offset)
        process_id = 1;
    else
        process_id = std::ceil(sc->id_offset / (float) ThreadConfig::get_instance_max());
}

unsigned Snort::get_process_id()
{ return process_id; }

void Snort::setup(int argc, char* argv[])
{
    set_main_thread();

    // must be done before any other files are opened because we
    // will try to grab file descriptor 3 (if --enable-stdlog)
    OpenLogger();

    init(argc, argv);
    const SnortConfig* sc = SnortConfig::get_conf();

    if ( sc->daemon_mode() )
        daemonize();

    // this must follow daemonization
    snort_main_thread_pid = gettid();

    /* Change groups */
    InitGroups(sc->get_uid(), sc->get_gid());

    set_quick_exit(false);

    memory::MemoryCap::start(*sc->memory, Stream::prune_flows);
    memory::MemoryCap::print(SnortConfig::log_verbose(), true);

    host_cache.init();
    ((HostTrackerModule*)PluginManager::get_module(HOST_TRACKER_NAME))->init_data();
    host_cache.print_config();

#ifdef USE_TSC_CLOCK
    // Call clock_scale once to determine internal ticks to time scale
    clock_scale();
#endif

    TimeStart();
}

void Snort::cleanup()
{
    TimeStop();

    SFDAQ::term();
    memory::MemoryCap::stop();

    if ( !SnortConfig::get_conf()->test_mode() )  // FIXIT-M ideally the check is in one place
        PrintStatistics();

    ThreadConfig::term();
    clean_exit(0);
    CloseLogger();
}

void Snort::reload_failure_cleanup(SnortConfig* sc)
{
    parser_term(sc);
    delete sc;
    set_default_policy(SnortConfig::get_conf());
    reloading = false;
    InspectorManager::abort_map();
}

void Snort::prepare_reload()
{
    IpsContextData::clear_ips_id();
}

// FIXIT-M refactor this so startup and reload call the same core function to
// instantiate things that can be reloaded
SnortConfig* Snort::get_reload_config(const char* fname)
{
    reloading = true;

    InspectorManager::new_map();
    ModuleManager::load_params();
    TraceApi::global_init();

    ModuleManager::reset_errors();
    reset_parse_errors();
    trim_heap();
    parser_init();

    if ( !fname )
        fname = get_snort_conf();

    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf, fname);

    if ( get_parse_errors() || ModuleManager::get_errors() || !sc->verify() )
    {
        reload_failure_cleanup(sc);
        return nullptr;
    }

    InspectorManager::prepare_map();
    TraceApi::capture_outputs(sc);
    sc->setup();

#ifdef SHELL
    ControlMgmt::reconfigure_controls();
#endif

    if ( get_parse_errors() or !InspectorManager::configure(sc) )
    {
        reload_failure_cleanup(sc);
        return nullptr;
    }

    InspectorManager::reconcile_map(sc);
    InspectorManager::prepare_inspectors(sc);

    FileService::verify_reload(sc);
    if ( get_reload_errors() )
    {
        reload_failure_cleanup(sc);
        return nullptr;
    }

    TraceApi::thread_reinit(sc->trace_config);

    if ( SnortConfig::log_verbose() )
    {
        PolicySelectorManager::print_config(sc);
        InspectorManager::print_config(sc);
    }

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

    if ( !sc->attribute_hosts_file.empty() )
    {
        if ( !HostAttributesManager::load_hosts_file(sc, sc->attribute_hosts_file.c_str()) )
            LogMessage("== WARNING: host attributes file failed to load\n");
    }
    HostAttributesManager::activate(sc);

    reloading = false;
    parser_term(sc);

    return sc;
}

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("Check process ID handling", "[snort_process_id]")
{
    // Mock first process
    snort::SnortConfig* sc = const_cast<snort::SnortConfig*>(snort::SnortConfig::get_conf());
    snort::ThreadConfig::set_instance_max(4);
    Snort::init_process_id();
    sc->id_offset = 0;
    unsigned pid1 = Snort::get_process_id();
    CHECK(pid1 == 1);

    // Mock second process
    sc->id_offset = 5;
    Snort::init_process_id();
    unsigned pid2 = Snort::get_process_id();
    CHECK(pid2 == 2);

    // Mock third process
    sc->id_offset = 9;
    Snort::init_process_id();
    unsigned pid3 = Snort::get_process_id();
    CHECK(pid3 == 3);

    // Mock fourth process
    sc->id_offset = 13;
    Snort::init_process_id();
    unsigned pid4 = Snort::get_process_id();
    CHECK(pid4 == 4);

    // Restore prior configs
    snort::ThreadConfig::set_instance_max(1);
    sc->id_offset = 0;
    Snort::init_process_id();
}

#endif

