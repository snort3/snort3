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

#include "cmd_line.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <syslog.h>
#include <iostream>
#include <string>
using namespace std;

#include "config_file.h"
#include "parser.h"
#include "vars.h"
#include "detection/detect.h"
#include "helpers/process.h"
#include "main/analyzer.h"
#include "managers/shell.h"
#include "managers/event_manager.h"
#include "managers/ips_manager.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "packet_io/trough.h"
#include "packet_io/sfdaq.h"
#include "packet_io/intf.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "helpers/markup.h"

#define LOG_NONE  "none"
#define LOG_TEXT  "text"
#define LOG_PCAP  "pcap"

#define ALERT_NONE    "none"
#define ALERT_PKT_CNT "packet-count"
#define ALERT_CMG     "cmg"
#define ALERT_JH      "jh"
#define ALERT_DJR     "djr"
#define ALERT_AJK     "ajk"

#define OUTPUT_AJK  "unified2"
#define OUTPUT_CMG  "alert_fast"
#define OUTPUT_LOG  "alert_syslog"
#define OUTPUT_PCAP "log_tcpdump"

static char* lua_conf = nullptr;
static char* snort_conf_dir = nullptr;

const char* get_snort_conf() { return lua_conf; }
const char* get_snort_conf_dir() { return snort_conf_dir; }

static void show_usage(const char* program_name);
static void show_options(const char* pfx);

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

static void SetSnortConfDir(const char* file)
{
    /* extract the config directory from the config filename */
    if ( file )
    {
        const char *path_sep = strrchr(file, '/');

        /* is there a directory seperator in the filename */
        if (path_sep != NULL)
        {
            path_sep++;  /* include path separator */
            snort_conf_dir = SnortStrndup(file, path_sep - file);
        }
        else
        {
            snort_conf_dir = SnortStrdup("./");
        }

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Config file = %s, config dir = "
                    "%s\n", file, snort_conf_dir););
    }
}

//-------------------------------------------------------------------------
// arg foo
//-------------------------------------------------------------------------

class ArgList
{
public:
    ArgList(int c, char* v[])
    { argc = c; argv = v; reset(); };

    void reset()
    { idx = 0; arg = nullptr; };

    bool get_arg(const char*& key, const char*& val);
    void dump();

private:
    char** argv;
    int argc, idx;
    const char* arg;
    string buf;
};

void ArgList::dump()
{
    for ( int i = 0; i < argc; ++i )
        printf("argv[%d]='%s'\n", i, argv[i]);
}

// FIXIT this chokes on -n -4 because it thinks
// -4 is another arg instead of an option to -n
bool ArgList::get_arg(const char*& key, const char*& val)
{
    while ( ++idx < argc )
    {
        char* s = argv[idx];

        if ( arg )
        {
            key = arg;
            if ( s[0] != '-' )
                val = s;
            else
            {
                val = "";
                --idx;
            }
            arg = nullptr;
            return true;
        }
        if ( s[0] != '-' )
        {
            key = "";
            val = s;
            return true;
        }
        if ( s[1] != '-' )
        {
            s += 1; 
            if ( strlen(s) > 1 )
            {
                buf.assign(s, 1);
                key = buf.c_str();
                val = s + 1;
                return true;
            }
            else if ( strlen(s) > 0 )
                arg = s;
            else
                arg = "-";
        }
        else
        {
            s += 2;
            char* eq = strchr(s, '=');

            if ( eq )
            {
                buf.assign(s, eq-s);
                key=buf.c_str();
                val = eq + 1;
                return true;
            }
            else
                arg = s;
        }
    }
    if ( arg )
    {
        key = arg;
        val = "";
        arg = nullptr;
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// config methods
//-------------------------------------------------------------------------

static long int loop_count = 0;

static void config_syslog(SnortConfig* sc, const char*)
{
    static bool syslog_configured = false;

    if (syslog_configured)
        return;

    /* If daemon or logging to syslog use "snort" as identifier and
     * start logging there now */
    openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);

    sc->logging_flags |= LOGGING_FLAG__SYSLOG;
    syslog_configured = true;
}

static void config_daemon(SnortConfig* sc, const char* val)
{
    static bool daemon_configured = false;

    if (daemon_configured)
        return;

    /* If daemon or logging to syslog use "snort" as identifier and
     * start logging there now */
    openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);

    ConfigDaemon(sc, val);
    daemon_configured = true;
}

static void config_daemon_restart(SnortConfig* sc, const char* val)
{
    sc->run_flags |= RUN_FLAG__DAEMON_RESTART;
    config_daemon(sc, val);
}

static void config_usage(SnortConfig*, const char* val)
{
    show_usage("snort");
    show_options(val);
    exit(1);
}

static void config_help_options(SnortConfig*, const char* val)
{
    show_options(val);
    exit(0);
}

static void config_help_signals(SnortConfig*, const char*)
{
    help_signals();
    exit(0);
}

enum HelpType {
    HT_CFG, HT_CMD, HT_GID, HT_IPS, HT_MOD, HT_BUF, HT_LST, HT_PLG
};

static void show_help(SnortConfig* sc, const char* val, HelpType ht)
{
    snort_conf = new SnortConfig;
    PluginManager::load_plugins(sc->plugin_path);
    ModuleManager::init();

    switch ( ht )
    {
    case HT_CFG:
        ModuleManager::show_configs(val);
        break;
    case HT_CMD:
        ModuleManager::show_commands(val);
        break;
    case HT_GID:
        ModuleManager::show_gids(val);
        break;
    case HT_IPS:
        ModuleManager::show_rules(val);
        break;
    case HT_MOD:
        ModuleManager::show_module(val);
        break;
    case HT_BUF:
        InspectorManager::dump_buffers();
        break;
    case HT_LST:
        ModuleManager::list_modules();
        break;
    case HT_PLG:
        PluginManager::list_plugins();
        break;
    }
    ModuleManager::term();
    PluginManager::release_plugins();
    delete snort_conf;
    exit(0);
}

static void config_help(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_CFG);
}

static void config_help_commands(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_CMD);
}

static void config_markup(SnortConfig*, const char*)
{
    Markup::enable();
}

static void config_help_gids(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_GID);
}

static void config_help_buffers(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_BUF);
}

static void config_help_builtin(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_IPS);
}

static void config_help_module(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_MOD);
}

static void config_list_modules(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_LST);
}

static void config_list_plugins(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_PLG);
}

static void config_lua(SnortConfig*, const char* val)
{
    Shell::set_overrides(val);
}

#ifdef UNIT_TEST
#include "test/unit_test.h"
static void config_unit_test(SnortConfig*, const char* val)
{
    unit_test_mode(val);
}
#endif

static void config_version(SnortConfig*, const char*)
{
    DisplayBanner();
    exit(0);
}

static void config_show_interfaces(SnortConfig*, const char*)
{
    DisplayBanner();
    PrintAllInterfaces();
    exit(0);
}

static void config_daq_list(SnortConfig* sc, const char* val)
{
    if ( val )
        ConfigDaqDir(sc, val);

    DAQ_Load(sc);
    DAQ_PrintTypes(stdout);
    DAQ_Unload();
    exit(0);
}

static void dump_dynamic_rules(SnortConfig* sc, const char* val)
{
    PluginManager::load_plugins(sc->plugin_path);
    IpsManager::dump_rule_stubs(val);
    exit(0);
}

static void config_nolock_pid_file(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__NO_LOCK_PID_FILE;
}

static void config_pause(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__PAUSE;
}

static void config_alert_mode(SnortConfig* sc, const char* val)
{
    if (strcasecmp(val, ALERT_NONE) == 0)
    {
        sc->output_flags |= OUTPUT_FLAG__NO_ALERT;
        EventManager::enable_alerts(false);
    }
    else if (strcasecmp(val, ALERT_PKT_CNT) == 0)
    {
        sc->output_flags |= OUTPUT_FLAG__ALERT_PKT_CNT;
    }
    else if ((strcasecmp(val, ALERT_CMG) == 0) ||
             (strcasecmp(val, ALERT_JH) == 0) ||
             (strcasecmp(val, ALERT_DJR) == 0))
    {
        sc->output = OUTPUT_CMG;
        sc->output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
        sc->output_flags |= OUTPUT_FLAG__APP_DATA;
    }
    else if (strcasecmp(val, ALERT_AJK) == 0)
    {
        sc->output = OUTPUT_AJK;
    }
    else
        sc->output = val;
}

static void config_conf(SnortConfig*, const char* val)
{
    lua_conf = SnortStrdup(val);
    SetSnortConfDir(lua_conf);
    set_main_hook(snort_inspect);
}

static void config_line_buffer(SnortConfig* sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__LINE_BUFFER;
}

static void config_log_id(SnortConfig* sc, const char* val)
{
    char *endptr;
    sc->event_log_id = SnortStrtoul(val, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0') ||
        (sc->event_log_id > UINT16_MAX))
    {
        FatalError("Snort log identifier invalid: %s.  It must "
                   "be between 0 and %u.\n", val, UINT16_MAX);
    }

    /* Forms upper 2 bytes.  Lower two bytes are the event id */
    sc->event_log_id <<= 16;

}

static void config_static_hash(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__STATIC_HASH;
}

static void config_remote_control(SnortConfig* sc, const char* val)
{
    sc->remote_control = atoi(val);  // FIXIT add to conf?
}

static void config_iface(SnortConfig*, const char* val)
{
    Trough_Multi(SOURCE_LIST, val);
}

static void config_log_mode(SnortConfig* sc, const char* val)
{
    if (strcasecmp(val, LOG_NONE) == 0)
    {
        sc->output_flags |= OUTPUT_FLAG__NO_LOG;
        set_main_hook(snort_ignore);
        EventManager::enable_logs(false);
    }
    else if (strcasecmp(val, LOG_TEXT) == 0)
    {
        set_main_hook(snort_print);
    }
    else if (strcasecmp(val, LOG_PCAP) == 0)
    {
        sc->output = OUTPUT_PCAP;
        set_main_hook(snort_log);
    }
    else
    {
        FatalError("Unknown -K option: %s\n", val);
    }
}

static void config_inline(SnortConfig* sc, const char*)
{
    LogMessage("Enabling inline operation\n");
    sc->run_flags |= RUN_FLAG__INLINE;
}

static void config_inline_test(SnortConfig* sc, const char*)
{
    LogMessage("Enable Inline Test Mode\n");
    sc->run_flags |= RUN_FLAG__INLINE_TEST;
}


static void config_test_mode(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__TEST;
}

#if !defined(NO_NON_ETHER_DECODER) && defined(DLT_IEEE802_11)
static void config_show_wifi_mgt(SnortConfig* sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__SHOW_WIFI_MGMT;
}
#endif
static void config_conf_error_out(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__CONF_ERROR_OUT;
}

static void config_max_threads(SnortConfig* sc, const char* val)
{
    sc->max_threads = atoi(val);
    if ( !sc->max_threads )
        sc->max_threads = -1; // max
}

static void config_trough_file(SnortConfig* sc, const char* val)
{
    Trough_Multi(SOURCE_FILE_LIST, val);
    sc->run_flags |= RUN_FLAG__READ;
}

static void config_trough_list(SnortConfig* sc, const char* val)
{
    Trough_Multi(SOURCE_LIST, val);
    sc->run_flags |= RUN_FLAG__READ;
}

static void config_trough_dir(SnortConfig* sc, const char* val)
{
    Trough_Multi(SOURCE_DIR, val);
    sc->run_flags |= RUN_FLAG__READ;
}

static void config_pcap_loop(SnortConfig*, const char* val)
{
    char *endptr;
    loop_count = SnortStrtol(val, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0') ||
        (loop_count < 0) || (loop_count > 2147483647))
    {
        FatalError("Valid values for --pcap-loop are between 0 and 2147483647\n");
    }

    if (loop_count == 0)
        Trough_SetLoopCount(-1);
    else
        Trough_SetLoopCount(loop_count);
}

static void config_pcap_reset(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__PCAP_RESET;
}

static void config_pcap_reload(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__PCAP_RELOAD;
}

static void config_pcap_filter(SnortConfig*, const char* val)
{
    Trough_SetFilter(val);
}

static void config_pcap_no_filter(SnortConfig*, const char*)
{
    Trough_SetFilter(NULL);
}


static void config_rule(SnortConfig*, const char* r)
{
    parser_append_rules(r);
}

static void config_pcap_show(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__PCAP_SHOW;
}

static void config_shell(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__SHELL;
}

static void config_bpf(SnortConfig* sc, const char* val)
{
    sc->bpf_filter = SnortStrdup(val);
}

static void config_pkt_count(SnortConfig* sc, const char* val)
{
    sc->pkt_cnt = strtol(val, nullptr, 0);
}

static void config_skip(SnortConfig* sc, const char* val)
{
    sc->pkt_skip = strtol(val, nullptr, 0);
}

static void config_ignore(SnortConfig*, const char*)
{ /* for basic opts already handled as spec opts */ }

typedef void (*ParseConfigFunc)(SnortConfig *, const char* val);

struct ConfigFunc
{
    const char *name;
    ParseConfigFunc parse_func;
    const char* help;
};

static ConfigFunc spec_opts[] =
{
    // stuff we need to do asap for maximum effect
    { "M", config_syslog, "" },
    { "E", config_daemon_restart, "" },
    { "D", config_daemon, "" },
    { "q", ConfigQuiet, "" },

    // stuff we do now because we are going to quit anyway
    { "W", config_show_interfaces, "" },
    { "?", config_usage, "" },

    { nullptr, nullptr, nullptr }
};

static ConfigFunc basic_opts[] =
{
    { "?", config_ignore,  // spec opt
      "show usage" },

    { "A", config_alert_mode, 
      "<mode> set alert mode: fast, full, console, test, unsock, or none " },

    { "B", ConfigObfuscationMask, 
      "<mask> obfuscated IP addresses in alerts and packet dumps using CIDR mask" },

    { "C", ConfigDumpCharsOnly, 
      "print out payloads with character data only (no hex)" },

    { "c", config_conf, 
      "<conf> use this configuration" },

    { "D", config_ignore, // spec opt
      "run Snort in background (daemon) mode" },

    { "d", ConfigDumpPayload, 
      "dump the Application Layer" },

    { "E", config_ignore, nullptr },  // spec opt

    { "e", ConfigDecodeDataLink, 
      "display the second layer header info" },

    { "f", config_line_buffer, 
      "turn off fflush() calls after binary log writes" },

    { "G", config_log_id, 
      "<0xid> (same as --logid)" },

    { "g", ConfigSetGid, 
      "<gname> run snort gid as <gname> group (or gid) after initialization" },

    { "H", config_static_hash, 
      "make hash tables deterministic" },

    { "i", config_iface, 
      "<iface>... list of interfaces" },

    { "j", config_remote_control,
      "set port to listen for telnet connections" },

    { "K", config_log_mode, 
      "<mode> logging mode (none(default), text, or pcap)" },

    { "k", ConfigChecksumMode, 
      "<mode> checksum mode (all,noip,notcp,noudp,noicmp,none)" },

    { "l", ConfigLogDir, 
      "<ld> log to directory <ld>" },

    { "M", config_ignore, // spec opt
      "log messages to syslog (not alerts)" },

    { "m", ConfigUmask, 
      "<umask> set umask = <umask>" },

    { "n", config_pkt_count, 
      "stop after n packets" },

    { "O", ConfigObfuscate, 
      "obfuscate the logged IP addresses" },

    { "Q", config_inline, 
      "enable inline mode operation" },

    { "q", config_ignore, // spec opt
      "quiet mode - Don't show banner and status report" },

    { "r", config_trough_list, 
      "<pcap>... (same as --pcap-list)" },

    { "S", config_set_var, 
      "<n=v> set rules file variable n equal to value v" },

    { "s", ConfigPacketSnaplen, 
      "<snap> (same as --snaplen)" },

    { "T", config_test_mode, 
      "test and report on the current Snort configuration" },

    { "t", ConfigChrootDir, 
      "<dir> chroots process to <dir> after initialization" },

    { "U", ConfigUtc, 
      "use UTC for timestamps" },

    { "u", ConfigSetUid, 
      "<uname> run snort uid as <uname> user (or uid) after initialization" },

    { "V", config_version, 
      "(same as --version)" },

    { "v", ConfigVerbose, 
      "be verbose" },

    { "W", config_ignore, // spec opt
      "lists available interfaces" },

#if !defined(NO_NON_ETHER_DECODER) && defined(DLT_IEEE802_11)
    { "w", config_show_wifi_mgt, 
      "dump 802.11 management and control frames" },
#endif

    { "X", ConfigDumpPayloadVerbose, 
      "dump the raw packet data starting at the link layer" },

    { "x", config_conf_error_out, 
      "exit on misconfiguration (same as --conf-error-out)" },

    { "y", ConfigShowYear, 
      "include year in timestamp in the alert and log files" },

    { "z", config_max_threads,
      "configure maximum number of packet threads (same as --max-packet-threads)" },

    { "alert-before-pass", ConfigAlertBeforePass,
      "process alert, drop, sdrop, or reject before pass; "
       "default is pass before alert, drop,..." },

    { "bpf", config_bpf,
      "<filter options> are standard BPF options, as seen in TCPDump" },

    { "conf-error-out", config_conf_error_out, 
      "exit if certain Snort configuration problems occur (same as -x)" },

    { "create-pidfile", ConfigCreatePidFile,
      "create PID file, even when not in Daemon mode" },

    { "daq", ConfigDaqType,
      "<type> select packet acquisition module (default is pcap)" },

    { "daq-dir", ConfigDaqDir,
      "<dir> tell snort where to find desired DAQ" },

    { "daq-list", config_daq_list,
      "list packet acquisition modules available in optional dir, default is static modules only" },

    { "daq-mode", ConfigDaqMode,
      "<mode> select the DAQ operating mode" },

    { "daq-var", ConfigDaqVar,
      "<name=value> specify extra DAQ configuration variable" },

    { "dump-dynamic-rules", dump_dynamic_rules,
      "<path> creates stub rule files of all loaded rules libraries" },

    { "dirty-pig", ConfigDirtyPig,
      "don't flush packets and release memory on shutdown" },

    { "enable-inline-test", config_inline_test,
      "enable Inline-Test Mode Operation" },

    { "help", config_help_options,
      "<option prefix> output matching command line option quick help" },

    { "help-builtin", config_help_builtin,
      "<module prefix> output matching builtin rules" },

    { "help-buffers", config_help_buffers,
      "output available inspection buffers" },

    { "help-commands", config_help_commands,
      "<module prefix> output matching commands" },

    { "help-config", config_help,
      "<module prefix> output matching config options" },

    { "help-gids", config_help_gids,
      "<module prefix> output matching generators" },

    { "help-module", config_help_module,
      "output description of given module" },

    { "help-options", config_help_options,
      "<option prefix> (same as --help)" },

    { "help-signals", config_help_signals,
      "dump available control signals" },

    { "list-modules", config_list_modules,
      "list all known modules" },

    { "list-plugins", config_list_plugins,
      "list all known modules" },

    { "lua", config_lua,
      "<chunk> extend/override conf with chunk; may be repeated" },

    { "logid", config_log_id,
      "<0xid> log Identifier to uniquely id events for multiple snorts (same as -G)" },

    { "markup", config_markup,
      "output help in asciidoc compatible format" },

    { "max-packet-threads", config_max_threads,
      "configure maximum number of packet threads (same as -z)" },

    { "nostamps", ConfigNoLoggingTimestamps,
      "don't include timestamps in log file names" },

    { "nolock-pidfile", config_nolock_pid_file,
      "do not try to lock Snort PID file" },

    { "pause", config_pause,
      "load config and wait for further commands before processing packets", },

    { "pcap-file", config_trough_file,
      "<file> file that contains a list of pcaps to read - read mode is implied" },

    { "pcap-list", config_trough_list,
      "<list> a space separated list of pcaps to read - read mode is implied" },

    { "pcap-dir", config_trough_dir,
      "<dir> a directory to recurse to look for pcaps - read mode is implied" },

    { "pcap-filter", config_pcap_filter,
      "<filter> filter to apply when getting pcaps from file or directory" },

    { "pcap-loop", config_pcap_loop,
      "<count> read all pcaps <count> times;  0 will read until Snort is terminated" },

    { "pcap-no-filter", config_pcap_no_filter,
      "reset to use no filter when getting pcaps from file or directory" },

    { "pcap-reload", config_pcap_reload,
      "if reading multiple pcaps, reload snort config between pcaps" },

    { "pcap-reset", config_pcap_reset,
      "reset Snort after each pcap" },

    { "pcap-show", config_pcap_show,
      "print a line saying what pcap is currently being read" },

    { "plugin-path", ConfigPluginPath,
      "where to find plugins" },

    { "process-all-events", ConfigProcessAllEvents,
      "process all action groups" },

    { "rule", config_rule,
      "add this line to rules configuration; may be repeated" },

    { "script-path", ConfigScriptPath,
      "where to find luajit scripts" },

    { "shell", config_shell,
      "enable the interactive command line", },

    { "skip", config_skip,
      "<n> skip 1st n packets", },

    { "snaplen", ConfigPacketSnaplen,
      "<snap> set snaplen of packet (same as -s)", },

    { "treat-drop-as-alert", ConfigTreatDropAsAlert,
      "converts drop, sdrop, and reject rules into alert rules during startup" },

    { "treat-drop-as-ignore", ConfigTreatDropAsIgnore,
      "use drop, sdrop, and reject rules to ignore session traffic when not inline" },

#ifdef UNIT_TEST
    { "unit-test", config_unit_test,
      "<verbosity> run unit tests with given libcheck output mode" },
#endif
    { "version", config_version,
      "show version number (same as -V)" },

    { nullptr, nullptr, nullptr }
};

static void check_flags(SnortConfig* sc)
{
    if ((sc->run_flags & RUN_FLAG__TEST) &&
        (sc->run_flags & RUN_FLAG__DAEMON))
    {
        FatalError("Cannot use test mode and daemon mode together.\n"
                   "To verify configuration, run first in test "
                   "mode and then restart in daemon mode.\n");
    }

    if ((sc->run_flags & RUN_FLAG__INLINE) &&
            (sc->run_flags & RUN_FLAG__INLINE_TEST))
    {
        FatalError("Cannot use inline adapter mode and inline test "
                "mode together. \n");
    }

    if (loop_count && !(sc->run_flags & RUN_FLAG__READ))
    {
        FatalError("--pcap-loop can only be used in combination with pcaps "
                   "on the command line.\n");
    }

    if ((sc->run_flags & RUN_FLAG__PCAP_RELOAD) &&
        !(sc->run_flags & RUN_FLAG__READ))
    {
        FatalError("--pcap-reload can only be used in combination with pcaps "
                   "on the command line.\n");
    }
}

SnortConfig* ParseCmdLine(int argc, char* argv[])
{
    SnortConfig* sc = SnortConfNew();

    ArgList al(argc, argv);
    const char* key, *val;

    // get special options first
    while ( al.get_arg(key, val) )
    {
        ConfigFunc* p = spec_opts;

        while ( p->name && strcmp(p->name, key) )
            ++p;

        if ( p->name )
            p->parse_func(sc, val);
    }

    // now get the rest
    al.reset();

    while ( al.get_arg(key, val) )
    {
        ConfigFunc* p = basic_opts;

        while ( p->name && strcmp(p->name, key) )
            ++p;

        if ( !p->name )
            FatalError("unknown arg '%s %s'\n", key, val);

        else
            p->parse_func(sc, val);
    }

    check_flags(sc);
    return sc;
}

//-------------------------------------------------------------------------

static void show_options(const char* pfx)
{
    ConfigFunc* p = basic_opts;
    unsigned n = pfx ? strlen(pfx) : 0;

    while ( p->name )
    {
        if ( p->help && (!n || !strncasecmp(p->name, pfx, n)) )
        {
            cout << Markup::item();
            cout << Markup::emphasis_on();

            const char* prefix = strlen(p->name) > 1 ? "--" : "-";
            cout << prefix << p->name;
            cout << Markup::emphasis_off();

            cout << " " << p->help;
            cout << endl;
        }
        ++p;
    }
}

static void show_usage(const char *program_name)
{
    fprintf(stdout, "USAGE: %s [-options] <filter options>\n", program_name);
}

//-------------------------------------------------------------------------

void set_daemon_args(int argc, char* argv[])
{
    for ( int i = 1; i < argc; ++i )
    {
        if ( !strcmp(argv[i], "-D") )
        {
            argv[i][1] = 'E';
            break;
        }
    }
}

//-------------------------------------------------------------------------

void cmd_line_term()
{
    if (lua_conf != NULL)
        free(lua_conf);

    if (snort_conf_dir != NULL)
        free(snort_conf_dir);
}

