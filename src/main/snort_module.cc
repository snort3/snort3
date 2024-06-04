//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// snort_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_module.h"

#include <set>
#include <string>

#include "detection/detect.h"
#include "detection/fp_detect.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "log/messages.h"
#include "main.h"
#include "managers/codec_manager.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/trough.h"
#include "parser/config_file.h"
#include "parser/parser.h"
#include "parser/parse_utils.h"
#include "parser/vars.h"
#include "trace/trace_api.h"
#include "trace/trace_config.h"
#include "utils/stats.h"

#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)
#include "catch/unit_test.h"
#endif

#include "analyzer.h"
#include "help.h"
#include "shell.h"
#include "snort_config.h"
#include "thread_config.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// commands
//-------------------------------------------------------------------------

#ifdef SHELL
static const Parameter s_reload[] =
{
    { "filename", Parameter::PT_STRING, nullptr, nullptr,
      "name of file to load" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_reload_w_path[] =
{
    { "filename", Parameter::PT_STRING, "(optional)", nullptr,
      "[<plugin path>] name of file to load" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_delete[] =
{
    { "inspector", Parameter::PT_STRING, nullptr, nullptr,
      "name of inspector to delete" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_module[] =
{
    { "module", Parameter::PT_STRING, nullptr, nullptr,
      "name of the module to reload" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_pktnum[] =
{
    { "pkt_num", Parameter::PT_INT, "1:max53", nullptr,
      "resume and pause after pkt_num packets" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_watchdog[] =
{
    { "timer", Parameter::PT_INT, "0:max32", nullptr,
      "timer for watchdog" },
    { "min_thread_count", Parameter::PT_INT, "0:max32", nullptr,
      "min thread count for watchdog" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter main_log_command_param[] =
{
    { "command", Parameter::PT_STRING, nullptr, nullptr, "<command> to update logging" },
    { "logging", Parameter::PT_BOOL, nullptr, nullptr, " true|false, enable or disable <command> logging" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter reset_stat_param[] =
{
	{ "type", Parameter::PT_STRING, nullptr, nullptr, "possible type can be: daq|module|appid|file_id|snort|ha|all." },
	{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command snort_cmds[] =
{
    { "set_watchdog_params", main_set_watchdog_params, s_watchdog, "set watchdog parameters" },
    { "show_plugins", main_dump_plugins, nullptr, "show available plugins" },

    { "delete_inspector", main_delete_inspector, s_delete,
      "delete an inspector from the default policy" },

    { "dump_stats", main_dump_stats, nullptr, "show summary statistics" },
    { "dump_heap_stats", main_dump_heap_stats, nullptr, "show heap statistics" },
    { "reset_stats", main_reset_stats, reset_stat_param, "clear summary statistics. "
      "Type can be: daq|module|appid|file_id|snort|ha|all. reset_stats() without a parameter clears all statistics."},
    { "rotate_stats", main_rotate_stats, nullptr, "roll perfmonitor log files" },
    { "reload_config", main_reload_config, s_reload_w_path, "load new configuration" },
    { "reload_policy", main_reload_policy, s_reload, "reload part or all of the default policy" },
    { "reload_daq", main_reload_daq, nullptr, "reload daq module" },
    { "reload_hosts", main_reload_hosts, s_reload, "load a new hosts table" },
    { "log_command", main_log_command,main_log_command_param, "enable or disable command logging"},
    { "show_config_generation", main_show_config_generation, nullptr, "show loaded configuration ID"},
    { "show_snort_cpu", show_snort_cpu, nullptr, "show snort cpu usage"},

    // FIXIT-M rewrite trough to permit updates on the fly
    //{ "process", main_process, nullptr, "process given pcap" },

    { "pause", main_pause, nullptr, "suspend packet processing", true },

    { "resume", main_resume, s_pktnum, "continue packet processing. "
      "If number of packets is specified, will resume for n packets and pause", true },

    { "detach", main_detach, nullptr, "detach from control shell (without shutting down)", true },
    { "quit", main_quit, nullptr, "shutdown and dump-stats", true },
    { "help", main_help, nullptr, "this output", true },

    { nullptr, nullptr, nullptr, nullptr }
};
#endif

//-------------------------------------------------------------------------
// hex conversion helper funcs
//-------------------------------------------------------------------------

[[noreturn]] static void c2x(const char* s)
{
    printf("'%c' = 0x%2.2X (%d)\n", s[0], s[0], s[0]);
    exit(0);
}

[[noreturn]] static void x2c(uint8_t x)
{
    printf("0x%2.2X (%u) = '%c'\n", x, x, static_cast<char>(x));
    exit(0);
}

[[noreturn]] static void x2s(const char* s)
{
    bool inv;
    string out, in = "\"";
    in += s;
    in += "\"";

    if ( parse_byte_code(in.c_str(), inv, out) )
        printf("%s = '%s'\n", s, out.c_str());

    else
        printf("%s = '%s'\n", s, "error");

    exit(0);
}

//-------------------------------------------------------------------------
// parameters
//
// users aren't used to seeing the standard help format for command line
// args so the few cases where there is a default, we include it in the
// help as well.
//
// command line options can be specified in Lua instead by doing e.g.
//
//     snort = { }; snort["-z"] = 2
//
// so a default value can't be provided for args that kick off optional
// run modes such as --rule-to-text because the program will do strange
// things like waiting on stdin for input that won't be coming.  in these
// cases the default must only be indicated in the help.
//-------------------------------------------------------------------------

static const TraceOption snort_trace_options[] =
{
    { "inspector_manager", TRACE_INSPECTOR_MANAGER, "enable inspector manager trace logging" },
#ifdef DEBUG_MSGS
    { "main", TRACE_MAIN, "enable main trace logging" },
#endif

    { nullptr, 0, nullptr }
};

static const Parameter s_params[] =
{
    { "-?", Parameter::PT_STRING, "(optional)", nullptr,
      "<option prefix> output matching command line option quick help (same as --help-options)" },

    // FIXIT-M should use PluginManager::get_available_plugins(PT_LOGGER)
    // but plugins not yet loaded upon set
    { "-A", Parameter::PT_STRING, nullptr, nullptr,
      "<mode> set alert mode: none, cmg, or alert_*" },

    { "-B", Parameter::PT_ADDR, nullptr, "255.255.255.255/32",
      "<mask> obfuscated IP addresses in alerts and packet dumps using CIDR mask" },

    { "-C", Parameter::PT_IMPLIED, nullptr, nullptr,
      "print out payloads with character data only (no hex)" },

    { "-c", Parameter::PT_STRING, nullptr, nullptr,
      "<conf> use this configuration" },

    { "-D", Parameter::PT_IMPLIED, nullptr, nullptr,
      "run Snort in background (daemon) mode" },

    { "-d", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump the Application Layer" },

    { "-e", Parameter::PT_IMPLIED, nullptr, nullptr,
      "display the second layer header info" },

    { "-f", Parameter::PT_IMPLIED, nullptr, nullptr,
      "turn off fflush() calls after binary log writes" },

    { "-G", Parameter::PT_INT, "0:65535", nullptr,
      "<0xid> (same as --logid)" },

    { "-g", Parameter::PT_STRING, nullptr, nullptr,
      "<gname> run snort gid as <gname> group (or gid) after initialization" },

    { "-H", Parameter::PT_IMPLIED, nullptr, nullptr,
      "make hash tables deterministic" },

    { "-h", Parameter::PT_IMPLIED, nullptr, nullptr,
      "show help overview (same as --help)" },

    { "-i", Parameter::PT_STRING, nullptr, nullptr,
      "<iface>... list of interfaces" },

#ifdef SHELL
    { "-j", Parameter::PT_PORT, nullptr, nullptr,
      "<port> to listen for Telnet connections" },
#endif

    { "-k", Parameter::PT_ENUM, "all|noip|notcp|noudp|noicmp|none", "all",
      "<mode> checksum mode; default is all" },

    { "-L", Parameter::PT_STRING, nullptr, nullptr,
      "<mode> logging mode (none, dump, pcap, or log_*)" },

    { "-l", Parameter::PT_STRING, nullptr, nullptr,
      "<logdir> log to this directory instead of current directory" },

    { "-M", Parameter::PT_IMPLIED, nullptr, nullptr,
      "log messages to syslog (not alerts)" },

    { "-m", Parameter::PT_INT, "0x000:0x1FF", nullptr,
      "<umask> set the process file mode creation mask" },

    { "-n", Parameter::PT_INT, "0:max53", nullptr,
      "<count> stop after count packets" },

    { "-O", Parameter::PT_IMPLIED, nullptr, nullptr,
      "obfuscate the logged IP addresses" },

    { "-Q", Parameter::PT_IMPLIED, nullptr, nullptr,
      "enable inline mode operation" },

    { "-q", Parameter::PT_IMPLIED, nullptr, nullptr,
      "quiet mode - suppress normal logging on stdout" },

    { "-R", Parameter::PT_STRING, nullptr, nullptr,
      "<rules> include this rules file in the default policy" },

    { "-r", Parameter::PT_STRING, nullptr, nullptr,
      "<pcap>... (same as --pcap-list)" },

    { "-s", Parameter::PT_INT, "0:65535", nullptr,
      "<snap> (same as --snaplen); default is 1518" },

    { "-T", Parameter::PT_IMPLIED, nullptr, nullptr,
      "test and report on the current Snort configuration" },

    { "-t", Parameter::PT_STRING, nullptr, nullptr,
      "<dir> chroots process to <dir> after initialization" },

    { "-U", Parameter::PT_IMPLIED, nullptr, nullptr,
      "use UTC for timestamps" },

    { "-u", Parameter::PT_STRING, nullptr, nullptr,
      "<uname> run snort as <uname> or <uid> after initialization" },

    { "-V", Parameter::PT_IMPLIED, nullptr, nullptr,
      "(same as --version)" },

    { "-v", Parameter::PT_IMPLIED, nullptr, nullptr,
      "be verbose" },

    { "-X", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump the raw packet data starting at the link layer" },

    { "-x", Parameter::PT_IMPLIED, nullptr, nullptr,
      "same as --pedantic" },

    { "-y", Parameter::PT_IMPLIED, nullptr, nullptr,
      "include year in timestamp in the alert and log files" },

    // do not provide parameter default as it will cause the value to change
    // after allocations in SnortConfig if snort = { } is set in Lua
    { "-z", Parameter::PT_INT, "0:max32", nullptr,
      "<count> maximum number of packet threads (same as --max-packet-threads); "
      "0 gets the number of CPU cores reported by the system; default is 1" },

    { "--alert-before-pass", Parameter::PT_IMPLIED, nullptr, nullptr,
      "evaluate alert rules before pass rules; default is pass rules first" },

    { "--bpf", Parameter::PT_STRING, nullptr, nullptr,
      "<filter options> are standard BPF options, as seen in TCPDump" },

    { "--c2x", Parameter::PT_STRING, nullptr, nullptr,
      "output hex for given char (see also --x2c)" },

#ifdef SHELL
    { "--control-socket", Parameter::PT_STRING, nullptr, nullptr,
      "<file> to create unix socket" },
#endif

    { "--create-pidfile", Parameter::PT_IMPLIED, nullptr, nullptr,
      "create PID file, even when not in Daemon mode" },

    { "--daq", Parameter::PT_STRING, nullptr, nullptr,
      "<type> select packet acquisition module (default is pcap)" },

    { "--daq-batch-size", Parameter::PT_INT, "1:", nullptr,
      "<size> set the DAQ receive batch size; default is 64", },

    { "--daq-dir", Parameter::PT_STRING, nullptr, nullptr,
      "<dir> tell snort where to find desired DAQ" },

    { "--daq-list", Parameter::PT_IMPLIED, nullptr, nullptr,
      "list packet acquisition modules available in optional dir, default is static modules only" },

    { "--daq-mode", Parameter::PT_ENUM, "passive | inline | read-file", nullptr,
      "<mode> select DAQ module operating mode (overrides automatic selection)" },

    { "--daq-var", Parameter::PT_STRING, nullptr, nullptr,
      "<name=value> specify extra DAQ configuration variable" },

    { "--dirty-pig", Parameter::PT_IMPLIED, nullptr, nullptr,
      "don't flush packets on shutdown" },

    { "--dump-builtin-options", Parameter::PT_STRING, nullptr, nullptr,
      "additional options to include with --dump-builtin-rules stubs" },

    { "--dump-builtin-rules", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module prefix>] output stub rules for selected modules" },

    { "--dump-config", Parameter::PT_SELECT, "all | top", nullptr,
      "dump config in json format" },

    { "--dump-config-text", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump config in text format" },

    // FIXIT-L add --list-dynamic-rules like --list-builtin-rules
    { "--dump-dynamic-rules", Parameter::PT_IMPLIED, nullptr, nullptr,
      "output stub rules for all loaded rules libraries" },

    { "--dump-defaults", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module prefix>] output module defaults in Lua format" },

    { "--dump-rule-databases", Parameter::PT_STRING, nullptr, nullptr,
      "dump rule databases to given directory (hyperscan only)" },

    { "--dump-rule-deps", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump rule dependencies in json format for use by other tools" },

    { "--dump-rule-meta", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump configured rule info in json format for use by other tools" },

    { "--dump-rule-state", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump configured rule state in json format for use by other tools" },

    { "--dump-version", Parameter::PT_IMPLIED, nullptr, nullptr,
      "output the version, the whole version, and only the version" },

    { "--enable-inline-test", Parameter::PT_IMPLIED, nullptr, nullptr,
      "enable Inline-Test Mode Operation" },

    { "--enable-test-features", Parameter::PT_IMPLIED, nullptr, nullptr,
      "enable features used in testing" },

    { "--gen-msg-map", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump configured rules in gen-msg.map format for use by other tools" },

    { "--help", Parameter::PT_IMPLIED, nullptr, nullptr,
      "show help overview" },

    { "--help-commands", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module prefix>] output matching commands" },

    { "--help-config", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module prefix>] output matching config options" },

    { "--help-counts", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module prefix>] output matching peg counts" },

    { "--help-limits", Parameter::PT_IMPLIED, nullptr, nullptr,
      "print the int upper bounds denoted by max*" },

    { "--help-module", Parameter::PT_STRING, nullptr, nullptr,
      "<module> output description of given module" },

    { "--help-modules", Parameter::PT_IMPLIED, nullptr, nullptr,
      "list all available modules with brief help" },

    { "--help-modules-json", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump description of all available modules in JSON format" },

    { "--help-options", Parameter::PT_STRING, "(optional)", nullptr,
      "[<option prefix>] output matching command line option quick help (same as -?)" },

    { "--help-plugins", Parameter::PT_IMPLIED, nullptr, nullptr,
      "list all available plugins with brief help" },

    { "--help-signals", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump available control signals" },

    { "--id-offset", Parameter::PT_INT, "0:65535", "0",
      "offset to add to instance IDs when logging to files" },

    { "--id-subdir", Parameter::PT_IMPLIED, nullptr, nullptr,
      "create/use instance subdirectories in logdir instead of instance filename prefix" },

    { "--id-zero", Parameter::PT_IMPLIED, nullptr, nullptr,
      "use id prefix / subdirectory even with one packet thread" },

    { "--include-path", Parameter::PT_STRING, nullptr, nullptr,
      "<path> where to find Lua and rule included files; "
      "searched before current or config directories" },

    { "--list-buffers", Parameter::PT_IMPLIED, nullptr, nullptr,
      "output available inspection buffers" },

    { "--list-builtin", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module prefix>] output matching builtin rules" },

    { "--list-gids", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module prefix>] output matching generators" },

    { "--list-modules", Parameter::PT_STRING, "(optional)", nullptr,
      "[<module type>] list all known modules of given type" },

    { "--list-plugins", Parameter::PT_IMPLIED, nullptr, nullptr,
      "list all known plugins" },

    { "--lua", Parameter::PT_STRING, nullptr, nullptr,
      "<chunk> extend/override conf with chunk; may be repeated" },

    { "--lua-sandbox", Parameter::PT_STRING, nullptr, nullptr,
      "<file> file that contains the lua sandbox environment in which config will be loaded" },

    { "--logid", Parameter::PT_INT, "0:65535", nullptr,
      "<0xid> log Identifier to uniquely id events for multiple snorts (same as -G)" },

    { "--markup", Parameter::PT_IMPLIED, nullptr, nullptr,
      "output help in asciidoc compatible format" },

    { "--max-packet-threads", Parameter::PT_INT, "0:max32", nullptr,
      "<count> configure maximum number of packet threads (same as -z)" },

    { "--mem-check", Parameter::PT_IMPLIED, nullptr, nullptr,
      "like -T but also compile search engines" },

    { "--metadata-filter", Parameter::PT_STRING, nullptr, nullptr,
      "<filter> load only rules containing filter string in metadata if set" },

    { "--nostamps", Parameter::PT_IMPLIED, nullptr, nullptr,
      "don't include timestamps in log file names" },

    { "--nolock-pidfile", Parameter::PT_IMPLIED, nullptr, nullptr,
      "do not try to lock Snort PID file" },

    { "--no-warn-flowbits", Parameter::PT_IMPLIED, nullptr, nullptr,
      "ignore warnings about flowbits that are checked but not set and vice-versa" },

    { "--no-warn-rules", Parameter::PT_IMPLIED, nullptr, nullptr,
      "ignore warnings about duplicate rules and rule parsing issues" },

    { "--pause", Parameter::PT_IMPLIED, nullptr, nullptr,
      "wait for resume/quit command before processing packets/terminating", },

#ifdef REG_TEST
    { "--pause-after-n", Parameter::PT_INT, "1:max53", nullptr,
      "<count> pause after count packets", },
#endif

    { "--pcap-file", Parameter::PT_STRING, nullptr, nullptr,
      "<file> file that contains a list of pcaps to read - read mode is implied" },

    { "--pcap-list", Parameter::PT_STRING, nullptr, nullptr,
      "<list> a space separated list of pcaps to read - read mode is implied" },

    { "--pcap-dir", Parameter::PT_STRING, nullptr, nullptr,
      "<dir> a directory to recurse to look for pcaps - read mode is implied" },

    { "--pcap-filter", Parameter::PT_STRING, nullptr, nullptr,
      "<filter> filter to apply when getting pcaps from file or directory" },

    { "--pcap-loop", Parameter::PT_INT, "0:max32", nullptr,
      "<count> read all pcaps <count> times;  0 will read until Snort is terminated" },

    { "--pcap-no-filter", Parameter::PT_IMPLIED, nullptr, nullptr,
      "reset to use no filter when getting pcaps from file or directory" },

    { "--pcap-show", Parameter::PT_IMPLIED, nullptr, nullptr,
      "print a line saying what pcap is currently being read" },

    { "--pedantic", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warnings are fatal" },

    { "--plugin-path", Parameter::PT_STRING, nullptr, nullptr,
      "<path> a colon separated list of directories or plugin libraries" },

    { "--process-all-events", Parameter::PT_IMPLIED, nullptr, nullptr,
      "process all action groups" },

    { "--rule", Parameter::PT_STRING, nullptr, nullptr,
      "<rules> to be added to configuration; may be repeated" },

    { "--rule-path", Parameter::PT_STRING, nullptr, nullptr,
      "<path> where to find rules files" },

    { "--rule-to-hex", Parameter::PT_IMPLIED, nullptr, nullptr,
      "output so rule header to stdout for text rule on stdin" },

    { "--rule-to-text", Parameter::PT_STRING, "16", nullptr,
      "output plain so rule header to stdout for text rule on stdin "
      "(specify delimiter or [Snort_SO_Rule] will be used)" },

    { "--run-prefix", Parameter::PT_STRING, nullptr, nullptr,
      "<pfx> prepend this to each output file" },

    { "--script-path", Parameter::PT_STRING, nullptr, nullptr,
      "<path> to a luajit script or directory containing luajit scripts" },

#ifdef SHELL
    { "--shell", Parameter::PT_IMPLIED, nullptr, nullptr,
      "enable the interactive command line", },
#endif

    { "--show-file-codes", Parameter::PT_IMPLIED, nullptr, nullptr,
      "indicate how files are located: A=absolute and W, F, C which are relative "
      "to the working directory, including file, and config file respectively" },

    { "--show-plugins", Parameter::PT_IMPLIED, nullptr, nullptr,
      "list module and plugin versions", },

    { "--skip", Parameter::PT_INT, "0:max53", nullptr,
      "<n> skip 1st n packets", },

    { "--snaplen", Parameter::PT_INT, "0:65535", nullptr,
      "<snap> set snaplen of packet (same as -s)", },

    { "--stdin-rules", Parameter::PT_IMPLIED, nullptr, nullptr,
      "read rules from stdin until EOF or a line starting with END is read", },

    { "--talos", Parameter::PT_IMPLIED, nullptr, nullptr,
      "enable Talos tweak (same as --tweaks talos)", },

    { "--tweaks", Parameter::PT_STRING, nullptr, nullptr,
      "tune configuration" },

#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)
    { "--catch-test", Parameter::PT_STRING, nullptr, nullptr,
      "comma separated list of Catch test tags or 'all'" },
#endif
    { "--version", Parameter::PT_IMPLIED, nullptr, nullptr,
      "show version number (same as -V)" },

    { "--warn-all", Parameter::PT_IMPLIED, nullptr, nullptr,
      "enable all warnings" },

    { "--warn-conf", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about configuration issues" },

    { "--warn-conf-strict", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about unrecognized elements in configuration files" },

    { "--warn-daq", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about DAQ issues, usually related to mode" },

    { "--warn-flowbits", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about flowbits that are checked but not set and vice-versa" },

    { "--warn-hosts", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about host table issues" },

    { "--warn-plugins", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about issues that prevent plugins from loading" },

    { "--warn-rules", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about duplicate rules and rule parsing issues" },

    { "--warn-scripts", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about issues discovered while processing Lua scripts" },

    { "--warn-symbols", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about unknown symbols in your Lua config" },

    { "--warn-vars", Parameter::PT_IMPLIED, nullptr, nullptr,
      "warn about variable definition and usage issues" },

    { "--x2c", Parameter::PT_INT, "0x00:0xFF", nullptr,
      "output ASCII char for given hex (see also --c2x)" },

    { "--x2s", Parameter::PT_STRING, nullptr, nullptr,
      "output ASCII string for given byte code (see also --x2c)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_name "snort"

#ifdef SHELL
#define s_help \
    "command line configuration and shell commands"
#else
#define s_help \
    "command line configuration"
#endif

THREAD_LOCAL const Trace* snort_trace = nullptr;

class SnortModule : public Module
{
public:
    SnortModule() : Module(s_name, s_help, s_params)
    { }

#ifdef SHELL
    const Command* get_commands() const override
    { return snort_cmds; }
#endif

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return proc_names; }

    PegCount* get_counts() const override
    { return (PegCount*)&proc_stats; }

    bool global_stats() const override
    { return true; }

    void sum_stats(bool) override
    { }  // accumulate externally

    void reset_stats() override
    {
        if (snort::in_main_thread())
            Module::reset_stats();
    }

    ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;

    Usage get_usage() const override
    { return GLOBAL; }

    void set_trace(const Trace*) const override;
    const TraceOption* get_trace_options() const override;

private:
    inline bool is(const Value& v, const char* opt);

    SFDAQModuleConfig* module_config = nullptr;
    bool no_warn_flowbits = false;
    bool no_warn_rules = false;
    std::string stub_opts;
    std::set<string> cli_opts;
    bool cli_mode = true;
};

void SnortModule::set_trace(const Trace* trace) const
{ snort_trace = trace; }

const TraceOption* SnortModule::get_trace_options() const
{
    return snort_trace_options;
}

bool SnortModule::begin(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(fqn, "snort"))
        module_config = nullptr;
    return true;
}

bool SnortModule::is(const Value& v, const char* opt)
{
    if ( !v.is(opt) )
        return false;

    if ( cli_mode )
        cli_opts.emplace(string(opt));
    else
        return cli_opts.end() == cli_opts.find(string(opt));

    return true;
}

bool SnortModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( is(v, "-?") )
        help_options(sc, v.get_string());

    else if ( is(v, "-A") )
        sc->set_alert_mode(v.get_string());

    else if ( is(v, "-B") )
        sc->set_obfuscation_mask(v.get_string());

    else if ( is(v, "-C") )
        sc->set_dump_chars_only(true);

    else if ( is(v, "-c") )
        config_conf(v.get_string());

    else if ( is(v, "-D") )
        sc->set_daemon(true);

    else if ( is(v, "-d") )
        sc->set_dump_payload(true);

    else if ( is(v, "-e") )
        sc->set_decode_data_link(true);

    else if ( is(v, "-f") )
        sc->output_flags |= OUTPUT_FLAG__LINE_BUFFER;

    else if ( is(v, "-G") || is(v, "--logid") )
        sc->event_log_id = v.get_uint16();

    else if ( is(v, "-g") )
        sc->set_gid(v.get_string());

    else if ( is(v, "-H") )
        sc->run_flags |= RUN_FLAG__STATIC_HASH;

    else if ( is(v, "-h") )
        help_basic(sc, v.get_string());

    else if ( is(v, "-i") )
        sc->daq_config->add_input(v.get_string());

#ifdef SHELL
    else if ( is(v, "-j") )
    {
        sc->remote_control_port = v.get_uint16();
        sc->remote_control_socket.clear();
    }
#endif

    else if ( is(v, "-k") )
        ConfigChecksumMode(v.get_string());

    else if ( is(v, "-L") )
        sc->set_log_mode(v.get_string());

    else if ( is(v, "-l") )
        sc->set_log_dir(v.get_string());

    else if ( is(v, "-M") )
        sc->enable_syslog();

    else if ( is(v, "-m") )
        sc->set_umask(v.get_uint32());

    else if ( is(v, "-n") )
        sc->pkt_cnt = v.get_uint64();

    else if ( is(v, "-O") )
        sc->set_obfuscate(true);

    else if ( is(v, "-Q") )
        sc->run_flags |= RUN_FLAG__INLINE;

    else if ( is(v, "-q") )
        SnortConfig::set_log_quiet(true);

    else if ( is(v, "-R") )
    {
        string s = "include ";
        s += v.get_string();
        parser_append_rules(s.c_str());
    }
    else if ( is(v, "-r") || is(v, "--pcap-list") )
    {
        sc->run_flags |= RUN_FLAG__READ;
        Trough::add_source(Trough::SOURCE_LIST, v.get_string());
    }

    else if ( is(v, "-s") or is(v, "--snaplen") )
        sc->daq_config->set_mru_size(v.get_uint16());

    else if ( is(v, "-T") )
        sc->run_flags |= RUN_FLAG__TEST;

    else if ( is(v, "-t") )
        sc->set_chroot_dir(v.get_string());

    else if ( is(v, "-U") )
        sc->set_utc(true);

    else if ( is(v, "-u") )
        sc->set_uid(v.get_string());

    else if ( is(v, "-V") )
        help_version(sc);

    else if ( is(v, "-v") )
        SnortConfig::enable_log_verbose();

    else if ( is(v, "-X") )
        sc->set_dump_payload_verbose(true);

    else if ( is(v, "-x") || is(v, "--pedantic") )
        sc->run_flags |= RUN_FLAG__CONF_ERROR_OUT;

    else if ( is(v, "-y") )
        sc->set_show_year(true);

    else if ( is(v, "-z") || is(v, "--max-packet-threads") )
        ThreadConfig::set_instance_max(v.get_uint32());

    else if ( is(v, "--alert-before-pass") )
        sc->set_alert_before_pass(true);

    else if ( is(v, "--bpf") )
        sc->bpf_filter = v.get_string();

    else if ( is(v, "--c2x") )
        c2x(v.get_string());

#ifdef SHELL
    else if ( is(v, "--control-socket") )
    {
        sc->remote_control_socket = v.get_string();
        sc->remote_control_port = 0;
    }
#endif

    else if ( is(v, "--create-pidfile") )
        sc->set_create_pid_file(true);

    else if ( is(v, "--daq") )
        module_config = sc->daq_config->add_module_config(v.get_string());

    else if ( is(v, "--daq-batch-size") )
        sc->daq_config->set_batch_size(v.get_uint32());

    else if ( is(v, "--daq-dir") )
    {
        stringstream ss { v.get_string() };
        string path;

        while ( getline(ss, path, ':') )
            sc->daq_config->add_module_dir(path.c_str());
    }
    else if ( is(v, "--daq-mode") )
    {
        if (!module_config)
            return false;
        switch ( v.get_uint8() )
        {
            case 0:
                module_config->mode = SFDAQModuleConfig::SFDAQ_MODE_PASSIVE;
                break;
            case 1:
                module_config->mode = SFDAQModuleConfig::SFDAQ_MODE_INLINE;
                break;
            case 2:
                module_config->mode = SFDAQModuleConfig::SFDAQ_MODE_READ_FILE;
                break;
        }
    }
    else if ( is(v, "--daq-list") )
        list_daqs(sc);

    else if ( is(v, "--daq-var") )
    {
        if (!module_config)
            return false;
        module_config->set_variable(v.get_string());
    }
    else if ( is(v, "--dirty-pig") )
        sc->set_dirty_pig(true);

    else if ( is(v, "--dump-builtin-options") )
        stub_opts = v.get_string();

    else if ( is(v, "--dump-builtin-rules") )
        dump_builtin_rules(sc, v.get_string(), stub_opts.c_str());

    else if ( is(v, "--dump-config") )
    {
        SnortConfig::set_log_quiet(true);
        sc->run_flags |= RUN_FLAG__TEST;
        if ( v.get_as_string() == "all" )
            sc->dump_config_type = DUMP_CONFIG_JSON_ALL;
        else if ( v.get_as_string() == "top" )
            sc->dump_config_type = DUMP_CONFIG_JSON_TOP;
    }

    else if ( is(v, "--dump-config-text") )
    {
        SnortConfig::set_log_quiet(true);
        sc->run_flags |= RUN_FLAG__TEST;
        sc->dump_config_type = DUMP_CONFIG_TEXT;
    }

    else if ( is(v, "--dump-dynamic-rules") )
        dump_dynamic_rules(sc, v.get_string());

    else if ( is(v, "--dump-defaults") )
        dump_defaults(sc, v.get_string());

    else if ( is(v, "--dump-rule-databases") )
    {
        sc->set_rule_db_dir(v.get_string());
        sc->run_flags |= (RUN_FLAG__TEST | RUN_FLAG__MEM_CHECK);
    }
    else if ( is(v, "--dump-rule-deps") )
    {
        sc->run_flags |= (RUN_FLAG__DUMP_RULE_DEPS | RUN_FLAG__TEST);
        SnortConfig::set_log_quiet(true);
    }
    else if ( is(v, "--dump-rule-meta") )
    {
        sc->run_flags |= (RUN_FLAG__DUMP_RULE_META | RUN_FLAG__TEST);
        sc->output_flags |= OUTPUT_FLAG__ALERT_REFS;
        SnortConfig::set_log_quiet(true);
    }
    else if ( is(v, "--dump-rule-state") )
    {
        sc->run_flags |= (RUN_FLAG__DUMP_RULE_STATE | RUN_FLAG__TEST);
        SnortConfig::set_log_quiet(true);
    }
    else if ( is(v, "--dump-version") )
        dump_version(sc);

    else if ( is(v, "--enable-inline-test") )
        sc->run_flags |= RUN_FLAG__INLINE_TEST;

    else if ( is(v, "--enable-test-features") )
    {
        sc->run_flags |= RUN_FLAG__TEST_FEATURES;
        SfIp::test_features = true;
    }

    else if ( is(v, "--gen-msg-map") )
    {
        sc->run_flags |= (RUN_FLAG__DUMP_MSG_MAP | RUN_FLAG__TEST);
        sc->output_flags |= OUTPUT_FLAG__ALERT_REFS;
        SnortConfig::set_log_quiet(true);
    }
    else if ( is(v, "--help") )
        help_basic(sc, v.get_string());

    else if ( is(v, "--help-commands") )
        help_commands(sc, v.get_string());

    else if ( is(v, "--help-config") )
        help_config(sc, v.get_string());

    else if ( is(v, "--help-counts") )
        help_counts(sc, v.get_string());

    else if ( is(v, "--help-limits") )
        help_limits(sc, v.get_string());

    else if ( is(v, "--help-module") )
        help_module(sc, v.get_string());

    else if ( is(v, "--help-modules") )
        help_modules(sc, v.get_string());

    else if ( is(v, "--help-modules-json") )
        help_modules_json(sc, v.get_string());

    else if ( is(v, "--help-options") )
        help_options(sc, v.get_string());

    else if ( is(v, "--help-plugins") )
        help_plugins(sc, v.get_string());

    else if ( is(v, "--help-signals") )
        help_signals(sc, v.get_string());

    else if ( is(v, "--id-offset") )
        sc->id_offset = v.get_uint16();

    else if ( is(v, "--id-subdir") )
        sc->id_subdir = true;

    else if ( is(v, "--id-zero") )
        sc->id_zero = true;

    else if ( is(v, "--include-path") )
        sc->set_include_path(v.get_string());

    else if ( is(v, "--list-buffers") )
        help_buffers(sc, v.get_string());

    else if ( is(v, "--list-builtin") )
        help_builtin(sc, v.get_string());

    else if ( is(v, "--list-gids") )
        help_gids(sc, v.get_string());

    else if ( is(v, "--list-modules") )
        list_modules(sc, v.get_string());

    else if ( is(v, "--list-plugins") )
        list_plugins(sc, v.get_string());

    else if ( is(v, "--lua") )
        sc->policy_map->get_shell()->set_overrides(v.get_string());

    else if ( is(v, "--lua-sandbox") )
        Shell::set_lua_sandbox(v.get_string());

    else if ( is(v, "--markup") )
        config_markup(sc, v.get_string());

    else if ( is(v, "--mem-check") )
        sc->run_flags |= (RUN_FLAG__TEST | RUN_FLAG__MEM_CHECK);

    else if ( is(v, "--metadata-filter") )
        sc->metadata_filter = v.get_string();

    else if ( is(v, "--nostamps") )
        sc->set_no_logging_timestamps(true);

    else if ( is(v, "--nolock-pidfile") )
        sc->run_flags |= RUN_FLAG__NO_LOCK_PID_FILE;

    else if ( is(v, "--no-warn-flowbits") )
        no_warn_flowbits = true;

    else if ( is(v, "--no-warn-rules") )
        no_warn_rules = true;

    else if ( is(v, "--pause") )
        sc->run_flags |= RUN_FLAG__PAUSE;

#ifdef REG_TEST
    else if ( is(v, "--pause-after-n") )
        sc->pkt_pause_cnt = v.get_uint64();
#endif

    else if ( is(v, "--pcap-file") )
    {
        sc->run_flags |= RUN_FLAG__READ;
        Trough::add_source(Trough::SOURCE_FILE_LIST, v.get_string());
    }
    else if ( is(v, "--pcap-dir") )
    {
        sc->run_flags |= RUN_FLAG__READ;
        Trough::add_source(Trough::SOURCE_DIR, v.get_string());
    }
    else if ( is(v, "--pcap-filter") )
        Trough::set_filter(v.get_string());

    else if ( is(v, "--pcap-loop") )
        Trough::set_loop_count(v.get_uint32());

    else if ( is(v, "--pcap-no-filter") )
        Trough::set_filter(nullptr);

    else if ( is(v, "--pcap-show") )
        sc->run_flags |= RUN_FLAG__PCAP_SHOW;

    else if ( is(v, "--plugin-path") )
        sc->add_plugin_path(v.get_string());

    else if ( is(v, "--process-all-events") )
        sc->set_process_all_events(true);

    else if ( is(v, "--rule") )
        parser_append_rules(v.get_string());

    else if ( is(v, "--rule-path") )
        parser_append_includes(v.get_string());

    else if ( is(v, "--rule-to-hex") )
        dump_rule_hex(sc, v.get_string());

    else if ( is(v, "--rule-to-text") )
        dump_rule_text(sc, v.get_string());

    else if ( is(v, "--run-prefix") )
        sc->run_prefix = v.get_string();

    else if ( is(v, "--script-path") )
        sc->add_script_path(v.get_string());

#ifdef SHELL
    else if ( is(v, "--shell") )
        sc->run_flags |= RUN_FLAG__SHELL;
#endif

    else if ( is(v, "--show-file-codes") )
        sc->run_flags |= RUN_FLAG__SHOW_FILE_CODES;

    else if ( is(v, "--show-plugins") )
        SnortConfig::enable_log_show_plugins();

    else if ( is(v, "--skip") )
        sc->pkt_skip = v.get_uint64();

    else if ( is(v, "--stdin-rules") )
        sc->stdin_rules = true;

    else if ( is(v, "--talos") )
        sc->set_tweaks("talos");

    else if ( is(v, "--tweaks") )
        sc->set_tweaks(v.get_string());

#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)
    else if ( is(v, "--catch-test") )
        catch_set_filter(v.get_string());
#endif
    else if ( is(v, "--version") )
        help_version(sc);

    else if ( is(v, "--warn-all") )
        sc->warning_flags = 0xFFFFFFFF;

    else if ( is(v, "--warn-conf") )
        sc->warning_flags |= (1 << WARN_CONF);

    else if ( is(v, "--warn-conf-strict") )
        sc->warning_flags |= (1 << WARN_CONF_STRICT);

    else if ( is(v, "--warn-daq") )
        sc->warning_flags |= (1 << WARN_DAQ);

    else if ( is(v, "--warn-flowbits") )
        sc->warning_flags |= (1 << WARN_FLOWBITS);

    else if ( is(v, "--warn-hosts") )
        sc->warning_flags |= (1 << WARN_HOSTS);

    else if ( is(v, "--warn-plugins") )
        sc->warning_flags |= (1 << WARN_PLUGINS);

    else if ( is(v, "--warn-rules") )
        sc->warning_flags |= (1 << WARN_RULES);

    else if ( is(v, "--warn-scripts") )
        sc->warning_flags |= (1 << WARN_SCRIPTS);

    else if ( is(v, "--warn-symbols") )
        sc->warning_flags |= (1 << WARN_SYMBOLS);

    else if ( is(v, "--warn-vars") )
        sc->warning_flags |= (1 << WARN_VARS);

    else if ( is(v, "--x2c") )
        x2c(v.get_uint8());

    else if ( is(v, "--x2s") )
        x2s(v.get_string());

    return true;
}

bool SnortModule::end(const char*, int, SnortConfig* sc)
{
    cli_mode = false;

    if ( sc->offload_threads and ThreadConfig::get_instance_max() != 1 )
        ParseError("You can not enable experimental offload with more than one packet thread.");

    if ( no_warn_flowbits )
    {
        sc->warning_flags &= ~(1 << WARN_FLOWBITS);
        no_warn_flowbits = false;
    }

    if ( no_warn_rules )
    {
        sc->warning_flags &= ~(1 << WARN_RULES);
        no_warn_rules = false;
    }

    return true;
}

ProfileStats* SnortModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = "daq";
        parent = nullptr;
        return &daqPerfStats;

    case 1:
        name = "decode";
        parent = nullptr;
        return &decodePerfStats;

    case 2:
        name = "mpse";
        parent = nullptr;
        return &mpsePerfStats;

    case 3:
        name = "rule_eval";
        parent = nullptr;
        return &rulePerfStats;

    case 4:
        name = "eventq";
        parent = nullptr;
        return &eventqPerfStats;
    }
    return nullptr;
}

//-------------------------------------------------------------------------
// singleton
//-------------------------------------------------------------------------

static SnortModule* snort_module = nullptr;

Module* get_snort_module()
{
    if ( !snort_module )
        snort_module = new SnortModule;

    return snort_module;
}

