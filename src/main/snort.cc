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

#include "snort.h"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <mutex>
#include <string>
using namespace std;

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <time.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#if !defined(CATCH_SEGV)
# include <sys/resource.h>
#endif

#include <thread>

#include "helpers/process.h"
#include "protocols/packet.h"
#include "packet_io/sfdaq.h"
#include "packet_io/active.h"
#include "rules.h"
#include "treenodes.h"
#include "snort_debug.h"
#include "main/snort_config.h"
#include "util.h"
#include "parser.h"
#include "packet_io/trough.h"
#include "tag.h"
#include "detect.h"
#include "mstring.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "filters/sfthreshold.h"
#include "filters/rate_filter.h"
#include "packet_time.h"
#include "perf_monitor/perf_base.h"
#include "perf_monitor/perf.h"
//#include "sflsq.h"
#include "ips_options/ips_flowbits.h"
#include "event_queue.h"
#include "framework/mpse.h"
#include "main/shell.h"
#include "main/analyzer.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/script_manager.h"
#include "managers/event_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/mpse_manager.h"
#include "protocols/packet_manager.h"
#include "managers/codec_manager.h"
#include "managers/action_manager.h"
#include "detection/sfrim.h"
#include "ppm.h"
#include "profiler.h"
#include "utils/strvec.h"
#include "packet_io/intf.h"
#include "detection_util.h"
#include "control/idle_processing.h"
#include "file_api/file_service.h"
#include "flow/flow_control.h"
#include "log/text_log.h"
#include "log/log_text.h"
#include "time/periodic.h"
#include "parser/config_file.h"
#include "parser/cmd_line.h"
#include "target_based/sftarget_reader.h"
#include "stream/stream_api.h"
#include "stream/stream.h"
#include "actions/act_replace.h"
#include "filters/detection_filter.h"

#ifdef INTEL_SOFT_CPM
#include "search/intel_soft_cpm.h"
#endif

//-------------------------------------------------------------------------

static THREAD_LOCAL Packet s_packet; // runtime variable.
THREAD_LOCAL SnortConfig* snort_conf = nullptr;
static SnortConfig* snort_cmd_line_conf = nullptr;

static bool snort_initializing = true;
static int snort_exiting = 0;

static pid_t snort_main_thread_pid = 0;

static int snort_argc = 0;
static char** snort_argv = NULL;

static void CleanExit(int);
static void SnortCleanup();

//-------------------------------------------------------------------------
// nascent policy management
//-------------------------------------------------------------------------
// FIXIT-H need stub binding rule to set these for runtime
// FIXIT-H need to set these on load too somehow

static THREAD_LOCAL NetworkPolicy* s_traffic_policy = nullptr;
static THREAD_LOCAL InspectionPolicy* s_inspection_policy = nullptr;
static THREAD_LOCAL IpsPolicy* s_detection_policy = nullptr;

NetworkPolicy* get_network_policy()
{ return s_traffic_policy; }

InspectionPolicy* get_inspection_policy()
{ return s_inspection_policy; }

IpsPolicy* get_ips_policy()
{ return s_detection_policy; }

void set_network_policy(NetworkPolicy* p)
{ s_traffic_policy = p; }

void set_inspection_policy(InspectionPolicy* p)
{ s_inspection_policy = p; }

void set_ips_policy(IpsPolicy* p)
{ s_detection_policy = p; }

//-------------------------------------------------------------------------
// utility
//-------------------------------------------------------------------------

#if 0
#ifdef HAVE_DAQ_ACQUIRE_WITH_META
static int MetaCallback(
    void* user, const DAQ_MetaHdr_t *metahdr, const uint8_t* data)
{
    PolicyId policy_id = getDefaultPolicy();
    SnortPolicy *policy;

    PROFILE_VARS;
    MODULE_PROFILE_START(metaPerfStats);

    policy = snort_conf->targeted_policies[policy_id];
    InspectorManager::dispatch_meta(policy->framework_policy, metahdr->type, data);

    MODULE_PROFILE_END(metaPerfStats);

    return 0;
}
#endif

static void SetupMetadataCallback(void)  // FIXDAQ
{
#ifdef HAVE_DAQ_ACQUIRE_WITH_META
    DAQ_Set_MetaCallback(&MetaCallback);
#endif
}
#endif

#if 0
// FIXIT-H restart foo
static void restart()
{
    int daemon_mode = ScDaemonMode();

    if ((!ScReadMode() && (getuid() != 0)) ||
        (snort_conf->chroot_dir != NULL))
    {
        LogMessage("Reload via Signal Reload does not work if you aren't root "
                   "or are chroot'ed.\n");
        /* We are restarting because of a configuration verification problem */
        CleanExit(1);
    }

    LogMessage("\n");
    LogMessage("** Restarting Snort **\n");
    LogMessage("\n");
    SnortCleanup();

    if (daemon_mode)
        set_daemon_args(snort_argc, snort_argv);

#ifdef PARANOID
    execv(snort_argv[0], snort_argv);
#else
    execvp(snort_argv[0], snort_argv);
#endif

    /* only get here if we failed to restart */
    LogMessage("Restarting %s failed: %s\n", snort_argv[0], get_error(errno));

    closelog();

    exit(-1);
}
#endif

//-------------------------------------------------------------------------
// perf stats
// FIXIT-M move these to appropriate modules
//-------------------------------------------------------------------------

#ifdef PERF_PROFILING
static ProfileStats* get_profile(const char* key)
{
    if ( !strcmp(key, "detect") )
        return &detectPerfStats;

    if ( !strcmp(key, "mpse") )
        return &mpsePerfStats;

    if ( !strcmp(key, "rule eval") )
        return &rulePerfStats;

    if ( !strcmp(key, "rtn eval") )
        return &ruleRTNEvalPerfStats;

    if ( !strcmp(key, "rule tree eval") )
        return &ruleOTNEvalPerfStats;

    if ( !strcmp(key, "decode") )
        return &decodePerfStats;

    if ( !strcmp(key, "eventq") )
        return &eventqPerfStats;

    if ( !strcmp(key, "total") )
        return &totalPerfStats;

    if ( !strcmp(key, "daq meta") )
        return &metaPerfStats;

    return nullptr;
}
#endif

static void register_profiles()
{
#ifdef PERF_PROFILING
    RegisterProfile("detect", nullptr, get_profile);
    RegisterProfile("mpse", "detect", get_profile);
    RegisterProfile("rule eval", "detect", get_profile);
    RegisterProfile("rtn eval", "rule eval", get_profile);
    RegisterProfile("rule tree eval", "rule eval", get_profile);
    RegisterProfile("decode", nullptr, get_profile);
    RegisterProfile("eventq", nullptr, get_profile);
    RegisterProfile("total", nullptr, get_profile);
    RegisterProfile("daq meta", nullptr, get_profile);
#endif
}

//-------------------------------------------------------------------------
// initialization
//-------------------------------------------------------------------------

static void init_policy(SnortConfig* sc)
{
    PolicyMode pm;

    if ( sc->run_flags & RUN_FLAG__INLINE )
        pm = POLICY_MODE__INLINE;

    else if ( sc->run_flags & RUN_FLAG__INLINE_TEST )
        pm =  POLICY_MODE__INLINE_TEST;

    else
        pm = POLICY_MODE__PASSIVE;

    sc->get_ips_policy()->policy_mode = pm;
}

static void SnortInit(int argc, char **argv)
{
    init_signals();

#if defined(NOCOREFILE)
    SetNoCores();
#else
    StoreSnortInfoStrings();
#endif

    /* chew up the command line */
    snort_cmd_line_conf = parse_cmd_line(argc, argv);
    snort_conf = snort_cmd_line_conf;

    /* Tell 'em who wrote it, and what "it" is */
    if (!ScLogQuiet())
        PrintVersion();

    InitProtoNames();
    SFAT_Init();

    LogMessage("--------------------------------------------------\n");

    ModuleManager::init();
    ScriptManager::load_scripts(snort_cmd_line_conf->script_path);
    PluginManager::load_plugins(snort_cmd_line_conf->plugin_path);
    ModuleManager::dump_modules();
    PluginManager::dump_plugins();

    FileAPIInit();
    register_profiles();

    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf);

    /* Merge the command line and config file confs to take care of
     * command line overriding config file.
     * Set the global snort_conf that will be used during run time */
    snort_conf = MergeSnortConfs(snort_cmd_line_conf, sc);
    init_policy(snort_conf);

    if ( snort_conf->output )
        EventManager::instantiate(snort_conf->output, sc);

    if (ScAlertBeforePass())
    {
        OrderRuleLists(snort_conf, "drop sdrop reject alert pass log");
    }
    if ( !InspectorManager::configure(snort_conf) )
        FatalError("can't initialize inspectors\n");

    if ( ScLogVerbose() )
        InspectorManager::print_config(snort_conf);

    ParseRules(snort_conf);

    // FIXIT-M print should be through generic module list 
    // and only print configured / active stuff
    //detection_filter_print_config(snort_conf->detection_filter_config);
    //RateFilter_PrintConfig(snort_conf->rate_filter_config);
    //print_thresholding(snort_conf->threshold_config, 0);
    //PrintRuleOrder(snort_conf->rule_lists);

    /* Check rule state lists, enable/disabled
     * and err on 'special' GID without OTN.
     */
    SetRuleStates(snort_conf);

    /* Need to do this after dynamic detection stuff is initialized, too */
    IpsManager::verify(snort_conf);

    if (snort_conf->file_mask != 0)
        umask(snort_conf->file_mask);
    else
        umask(077);    /* set default to be sane */

    IpsManager::global_init(snort_conf);

    fpCreateFastPacketDetection(snort_conf);
    MpseManager::activate_search_engine(snort_conf);
    CodecManager::instantiate();
    SFAT_Start();

#ifdef PPM_MGR
    PPM_PRINT_CFG(&snort_conf->ppm_cfg);
#endif

    /* Finish up the pcap list and put in the queues */
    Trough_SetUp();

    // FIXIT-L stuff like this that is also done in snort_config.cc::VerifyReload()
    // should be refactored
    if ((snort_conf->bpf_filter == NULL) && (snort_conf->bpf_file != NULL))
        snort_conf->bpf_filter = read_infile(snort_conf->bpf_file);

    if (snort_conf->bpf_filter != NULL)
        LogMessage("Snort BPF option: %s\n", snort_conf->bpf_filter);

    if (ScOutputUseUtc())
        snort_conf->thiszone = 0;
#ifndef VALGRIND_TESTING
    else
        snort_conf->thiszone = gmt2local(0);
#endif
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
// much initialization stuff in SnortInit() as possible and to restrict this
// function to those things that depend on DAQ startup or non-root user/group.
//
// FIXIT-J breaks DAQ_New()/Start() because packet threads won't be root when
// opening iface
static void SnortUnprivilegedInit(void)
{
    /* create the PID file */
    if ( !ScReadMode() && (ScDaemonMode() || ScCreatePidFile()))
    {
        CreatePidFile(snort_main_thread_pid);
    }

    /* Drop the Chrooted Settings */
    if (snort_conf->chroot_dir)
        SetChroot(snort_conf->chroot_dir, &snort_conf->log_dir);

    /* Drop privileges if requested, when initialization is done */
    SetUidGid(ScUid(), ScGid());

    snort_initializing = false;
}

void snort_setup(int argc, char* argv[])
{
    snort_argc = argc;
    snort_argv = argv;

    OpenLogger();

    SnortInit(argc, argv);

    LogMessage("%s\n", LOG_DIV);
    DAQ_Init(snort_conf);

    if ( ScDaemonMode() )
        daemonize();

    // this must follow daemonization
    snort_main_thread_pid = gettid();

    /* Change groups */
    InitGroups(ScUid(), ScGid());
    SnortUnprivilegedInit();

    if ( int k = get_parse_errors() )
        FatalError("see prior %d errors\n", k);

    set_quick_exit(false);
}

//-------------------------------------------------------------------------
// termination
//-------------------------------------------------------------------------

static void CleanExit(int)
{
    SnortConfig tmp;

    /* Have to trick LogMessage to log correctly after snort_conf
     * is freed */
    memset(&tmp, 0, sizeof(tmp));

    if (snort_conf != NULL)
    {
        tmp.logging_flags |=
            (snort_conf->logging_flags & LOGGING_FLAG__QUIET);

        tmp.run_flags |= (snort_conf->run_flags & RUN_FLAG__DAEMON);

        tmp.logging_flags |=
            (snort_conf->logging_flags & LOGGING_FLAG__SYSLOG);
    }

    SnortCleanup();
    snort_conf = &tmp;

    LogMessage("Snort exiting\n");
    closelog();
}

static void SnortCleanup()
{
    /* This function can be called more than once.  For example,
     * once from the SIGINT signal handler, and once recursively
     * as a result of calling pcap_close() below.  We only need
     * to perform the cleanup once, however.  So the static
     * variable already_exiting will act as a flag to prevent
     * double-freeing any memory.  Not guaranteed to be
     * thread-safe, but it will prevent the simple cases.
     */
    static int already_exiting = 0;
    if( already_exiting != 0 )
    {
        return;
    }
    already_exiting = 1;
    snort_exiting = 1;
    snort_initializing = false;  /* just in case we cut out early */

    IdleProcessingCleanUp();

    IpsManager::global_term(snort_conf);
    SFAT_Cleanup();
    Trough_CleanUp();
    ClosePidFile();

    /* remove pid file */
    if ( snort_conf->pid_filename[0] )
    {
        int ret;

        ret = unlink(snort_conf->pid_filename);

        if (ret != 0)
        {
            ErrorMessage("Could not remove pid file %s: %s\n",
                         snort_conf->pid_filename, get_error(errno));
        }
    }

    //MpseManager::print_search_engine_stats();

    close_fileAPI();

    sfthreshold_free();  // FIXDAQ etc.
    RateFilter_Cleanup();

    periodic_release();
    ParserCleanup();

#ifdef PERF_PROFILING
    CleanupProfileStatsNodeList();
#endif

    /* free allocated memory */
    if (snort_conf == snort_cmd_line_conf)
    {
        SnortConfFree(snort_cmd_line_conf);
        snort_cmd_line_conf = NULL;
        snort_conf = NULL;
    }
    else
    {
        SnortConfFree(snort_cmd_line_conf);
        snort_cmd_line_conf = NULL;
        SnortConfFree(snort_conf);
        snort_conf = NULL;
    }
    CleanupProtoNames();
    ModuleManager::term();
    PluginManager::release_plugins();
}

void snort_cleanup()
{
    DAQ_Term();

    if ( !ScTestMode() )  // FIXIT-M ideally the check is in one place
        PrintStatistics();

    CloseLogger();
    CleanExit(0);
}

//-------------------------------------------------------------------------
// reload foo
//-------------------------------------------------------------------------

// FIXIT-M refactor this so startup and reload call the same core function to
// instantiate things that can be reloaded
static SnortConfig * get_reload_config(void)
{
    SnortConfig *sc = ParseSnortConf(snort_cmd_line_conf);

    sc = MergeSnortConfs(snort_cmd_line_conf, sc);
    init_policy(sc);

    if (VerifyReload(sc) == -1)
    {
        SnortConfFree(sc);
        return NULL;
    }

    if (sc->output_flags & OUTPUT_FLAG__USE_UTC)
        sc->thiszone = 0;
#ifndef VALGRIND_TESTING
    else
        sc->thiszone = gmt2local(0);
#endif

    if ( !InspectorManager::configure(sc) )
    {
        SnortConfFree(sc);
        return NULL;
    }

    FlowbitResetCounts();
    ParseRules(sc);

    // FIXIT-L see SnortInit() on config printing
    //detection_filter_print_config(sc->detection_filter_config);
    ////RateFilter_PrintConfig(sc->rate_filter_config);
    //print_thresholding(sc->threshold_config, 0);
    //PrintRuleOrder(sc->rule_lists);

    SetRuleStates(sc);

    /* Need to do this after dynamic detection stuff is initialized, too */
    IpsManager::verify(sc);

    if ((sc->file_mask != 0) && (sc->file_mask != snort_conf->file_mask))
        umask(sc->file_mask);

    /* Transfer any user defined rule type outputs to the new rule list */
    {
        RuleListNode *cur = snort_conf->rule_lists;

        for (; cur != NULL; cur = cur->next)
        {
            RuleListNode *rnew = sc->rule_lists;

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

    fpCreateFastPacketDetection(sc);

    if ( sc->fast_pattern_config->search_api !=
            snort_conf->fast_pattern_config->search_api )
    {
        MpseManager::activate_search_engine(sc);
    }

#ifdef PPM_MGR
    PPM_PRINT_CFG(&sc->ppm_cfg);
#endif

    return sc;
}

SnortConfig* reload_config()
{
    SnortConfig* new_conf = get_reload_config();

    if ( new_conf )
    {
        proc_stats.conf_reloads++;
        snort_conf = new_conf;
    }
    return new_conf;
}

//-------------------------------------------------------------------------
// runtime foo
//-------------------------------------------------------------------------

// non-local for easy access from core
//static THREAD_LOCAL Packet s_packet;  declared above due to initalization in CodecManager
static THREAD_LOCAL DAQ_PktHdr_t s_pkth;
static THREAD_LOCAL uint8_t s_data[65536];

static void pass_pkts(Packet*) { }
static MainHook_f main_hook = pass_pkts;

void set_main_hook(MainHook_f f)
{ main_hook = f; }

Packet* get_current_packet()
{ return &s_packet; }

// FIXIT-J for multiple packet threads
// using thread locals for s_pkth and s_data won't work
// will need array of s_packet, s_pkth, and s_data and 
// capture all if it is not clear which thread crashed
void CapturePacket()
{
    if ( s_packet.pkth )
    {
        s_pkth = *s_packet.pkth;

        if ( s_packet.pkt )
            memcpy(s_data, s_packet.pkt, 0xFFFF & s_packet.pkth->caplen);
    }
}

void set_default_policy()
{
    set_network_policy(snort_conf->policy_map->network_policy[0]);
    set_ips_policy(snort_conf->policy_map->ips_policy[0]);
    set_inspection_policy(snort_conf->policy_map->inspection_policy[0]);
}

static void set_policy(Packet*)  // FIX SSN implement based on bindings
{
   // for now need to just get stream_* inspectors and call appropriately 
#if 0
    int vlanId = (p->vh) ? vlan::vth_vlan(p->vh) : -1;
    const sfip_t *srcIp = p->ptrs.ip_api.get_src(); // returns nullptr if not set
    const sfip_t *dstIp = p->ptrs.ip_api.get_dst();

    //set policy id for this packet
    setCurrentPolicy(snort_conf, sfGetApplicablePolicyId(
        snort_conf->policy_config, vlanId, srcIp, dstIp));
#else
    set_default_policy();
#endif
}

void DecodeRebuiltPacket (
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt, 
    Flow* lws)
{
    SnortEventqPush();
    PacketManager::decode(p, pkthdr, pkt);

    p->flow = lws;

    set_policy(p);  // FIX SSN rebuilt should reuse original bindings
    p->user_policy_id = get_ips_policy()->user_policy_id;

    SnortEventqPop();
}

void DetectRebuiltPacket (Packet* p)
{
    int tmp_do_detect = do_detect;
    int tmp_do_detect_content = do_detect_content;

    SnortEventqPush();
    main_hook(p);
    SnortEventqPop();

    DetectReset();
    do_detect = tmp_do_detect;
    do_detect_content = tmp_do_detect_content;
}

void LogRebuiltPacket (Packet* p)
{
    SnortEventqPush();
    SnortEventqLog(p);
    SnortEventqReset();
    SnortEventqPop();
}

DAQ_Verdict ProcessPacket(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    DAQ_Verdict verdict = DAQ_VERDICT_PASS;

    set_default_policy();

    PacketManager::decode(p, pkthdr, pkt);
    assert(p->pkth && p->pkt);

    if ( !p->proto_bits )
        p->proto_bits = PROTO_BIT__OTHER;

#if 0
    // FIXIT-J required until decoders are fixed
    else if ( !p->family && (p->proto_bits & PROTO_BIT__IP) )
        p->proto_bits &= ~PROTO_BIT__IP;
#endif

    set_policy(p);

    p->user_policy_id = get_ips_policy()->user_policy_id;

    /* just throw away the packet if we are configured to ignore this port */
    if ( !(p->packet_flags & PKT_IGNORE) )
    {
        DetectReset();
        main_hook(p);
    }

    if ( Active_SessionWasDropped() )
    {
        if ( !Active_PacketForceDropped() )
            Active_DropAction(p);
        else
            Active_ForceDropAction(p);

        if ( Active_GetTunnelBypass() )
        {
            pc.internal_blacklist++;
            return verdict;
        }

        if ( ScInlineMode() || Active_PacketForceDropped() )
            verdict = DAQ_VERDICT_BLACKLIST;
        else
            verdict = DAQ_VERDICT_IGNORE;
    }

    return verdict;
}

DAQ_Verdict fail_open(
    void*, const DAQ_PktHdr_t*, const uint8_t*)
{
    pc.total_fail_open++;
    return DAQ_VERDICT_PASS;
}

DAQ_Verdict packet_callback(
    void*, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    int inject = 0;
    DAQ_Verdict verdict = DAQ_VERDICT_PASS;
    PROFILE_VARS;

    MODULE_PROFILE_START(totalPerfStats);

    pc.total_from_daq++;

    /* Increment counter that we're evaling rules for caching results */
    rule_eval_pkt_count++;

    /* Save off the time of each and every packet */
    packet_time_update(&pkthdr->ts);

    if ( snort_conf->pkt_skip && pc.total_from_daq <= snort_conf->pkt_skip )
    {
        MODULE_PROFILE_END(totalPerfStats);
        return verdict;
    }

    /* reset the thresholding subsystem checks for this packet */
    sfthreshold_reset();

    MODULE_PROFILE_START(eventqPerfStats);
    SnortEventqReset();
    MODULE_PROFILE_END(eventqPerfStats);

    ActionManager::reset_queue();

    verdict = ProcessPacket(&s_packet, pkthdr, pkt);

    ActionManager::execute(&s_packet);

    if ( Active_PacketWasDropped() )
    {
        if ( verdict == DAQ_VERDICT_PASS )
            verdict = DAQ_VERDICT_BLOCK;
    }
    else
    {
        Packet* p = &s_packet;
        if ( s_packet.packet_flags & PKT_MODIFIED )
        {
            // this packet was normalized and/or has replacements
            PacketManager::encode_update(&s_packet);
            verdict = DAQ_VERDICT_REPLACE;
        }
        else if ( p->packet_flags & PKT_RESIZED )
        {
            printf("packet flags = 0x%X\n", p->packet_flags);
            // we never increase, only trim, but
            // daq doesn't support resizing wire packet
            if ( !DAQ_Inject(s_packet.pkth, 0, s_packet.pkt, s_packet.pkth->pktlen) )
            {
                verdict = DAQ_VERDICT_BLOCK;
                inject = 1;
            }
        }
        else
        {
            if ( (s_packet.packet_flags & PKT_IGNORE) ||
                (stream.get_ignore_direction(s_packet.flow) == SSN_DIR_BOTH) )
            {
                if ( !Active_GetTunnelBypass() )
                {
                    verdict = DAQ_VERDICT_WHITELIST;
                }
                else
                {
                    verdict = DAQ_VERDICT_PASS;
                    pc.internal_whitelist++;
                }
            }
            else if ( s_packet.ptrs.decode_flags & DECODE_PKT_TRUST )
            {
                stream.set_ignore_direction(s_packet.flow, SSN_DIR_BOTH);

                verdict = DAQ_VERDICT_WHITELIST;
            }
            else
            {
                verdict = DAQ_VERDICT_PASS;
            }
        }
    }

    /* Collect some "on the wire" stats about packet size, etc */
    UpdateWireStats(&sfBase, pkthdr->caplen, Active_PacketWasDropped(), inject);
    Active_Reset();
    PacketManager::encode_reset();

    if ( flow_con ) // FIXIT-H always instantiate
    {
        flow_con->timeout_flows(4, pkthdr->ts.tv_sec);
    }

    s_packet.pkth = NULL;  // no longer avail on segv

    if ( snort_conf->pkt_cnt && pc.total_from_daq >= snort_conf->pkt_cnt )
        DAQ_BreakLoop(-1);

    MODULE_PROFILE_END(totalPerfStats);
    return verdict;
}

void snort_idle()
{
    if ( flow_con )
        flow_con->timeout_flows(16384, time(NULL));
    pc.idle++;
}

void snort_rotate()
{
    SetRotatePerfFileFlag();
}

void snort_thread_init(const char* intf)
{
    // FIXIT-J the start-up sequence is a little off due to dropping privs
    DAQ_New(snort_conf, intf);
    DAQ_Start();

    CodecManager::thread_init(snort_conf, s_packet);
    FileAPIPostInit();

    // this depends on instantiated daq capabilities
    // so it is done here instead of SnortInit()
    Active_Init(snort_conf);

    SnortEventqNew(snort_conf->event_queue_config);

    InitTag();

    EventTrace_Init();
    detection_filter_init(snort_conf->detection_filter_config);

    otnx_match_data_init(snort_conf->num_rule_types);

    EventManager::open_outputs();
    IpsManager::setup_options();
    ActionManager::thread_init(snort_conf);
    InspectorManager::thread_init(snort_conf);
}

void snort_thread_term()
{
#ifdef PPM_MGR
    ppm_sum_stats();
#endif
    ModuleManager::accumulate(snort_conf);
    InspectorManager::thread_term(snort_conf);
    ActionManager::thread_term(snort_conf);
    IpsManager::clear_options();
    EventManager::close_outputs();
    CodecManager::thread_term(s_packet);

    if ( DAQ_WasStarted() )
        DAQ_Stop();

    DAQ_Delete();

    if ( snort_conf->dirty_pig )
        return;

#ifdef PERF_PROFILING
    ReleaseProfileStats();
#endif

    otnx_match_data_term();
    detection_filter_term();
    EventTrace_Term();
    CleanupTag();

    SnortEventqFree();
    Active_Term();
}

