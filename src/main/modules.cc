/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// modules.cc author Russ Combs <rucombs@cisco.com>

#include "modules.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include <string>
using namespace std;

#include "framework/module.h"
#include "managers/module_manager.h"
#include "main.h"
#include "snort.h"
#include "snort_config.h"
#include "parser/parser.h"
#include "parser/parse_conf.h"
#include "parser/config_file.h"
#include "parser/cmd_line.h"
#include "detection/signature.h"
#include "ips_options/ips_flowbits.h"
#include "file_api/libs/file_config.h"
#include "filters/sfthd.h"
#include "filters/sfrf.h"
#include "filters/rate_filter.h"
#include "codecs/decode_module.h"
#include "time/ppm_module.h"
#include "parser/parse_ip.h"
#include "target_based/sftarget_data.h"

#if defined(DEBUG_MSGS) || defined (REG_TEST)
#include "file_api/file_api.h"
#endif

//-------------------------------------------------------------------------
// detection module
//-------------------------------------------------------------------------

static const Parameter detection_params[] =
{
    { "asn1", Parameter::PT_INT, "1:", "256",
      "maximum decode nodes" },

    { "pcre_enable", Parameter::PT_BOOL, nullptr, "true",
      "disable pcre pattern matching" },

    { "pcre_match_limit", Parameter::PT_INT, "-1:1000000", "1500",
      "limit pcre backtracking, -1 = max, 0 = off" },

    { "pcre_match_limit_recursion", Parameter::PT_INT, "-1:10000", "1500",
      "limit pcre stack consumption, -1 = max, 0 = off" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class DetectionModule : public Module
{
public:
    DetectionModule() : Module("detection", detection_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool DetectionModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("asn1") )
        sc->asn1_mem = v.get_long();

    else if ( v.is("pcre_enable") )
    {
        if ( v.get_bool() )
            sc->run_flags &= ~RUN_FLAG__NO_PCRE;
        else
            sc->run_flags |= RUN_FLAG__NO_PCRE;
    }
    else if ( v.is("pcre_match_limit") )
        sc->pcre_match_limit = v.get_long();

    else if ( v.is("pcre_match_limit_recursion") )
        sc->pcre_match_limit_recursion = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// event queue module
//-------------------------------------------------------------------------

static const Parameter event_queue_params[] =
{
    { "max_queue", Parameter::PT_INT, "1:", "8",
      "maximum events to queue" },

    { "log", Parameter::PT_INT, "1:", "3",
      "maximum events to log" },

    { "order_events", Parameter::PT_ENUM,
      "priority|content_length", "content_length",
      "criteria for ordering incoming events" },

    { "process_all_events", Parameter::PT_BOOL, nullptr, "false",
      "process just first action group or all action groups" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class EventQueueModule : public Module
{
public:
    EventQueueModule() : Module("event_queue", event_queue_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool EventQueueModule::set(const char*, Value& v, SnortConfig* sc)
{
    EventQueueConfig* eq = sc->event_queue_config;

    if ( v.is("max_queue") )
        eq->max_events = v.get_long();

    else if ( v.is("log") )
        eq->log_events = v.get_long();

    else if ( v.is("order_events") )
    {
        if ( v.get_long() )
            eq->order = SNORT_EVENTQ_CONTENT_LEN;
        else
            eq->order = SNORT_EVENTQ_PRIORITY;
    }
    else if ( v.is("process_all_events") )
        eq->process_all_events = v.get_bool();

    else
        return false;

    if ( eq->max_events < eq->log_events )
        eq->max_events = eq->log_events;

    return true;
}

//-------------------------------------------------------------------------
// search engine module
//-------------------------------------------------------------------------

static const Parameter search_engine_params[] =
{
    { "bleedover_port_limit", Parameter::PT_INT, "1:", "1024",
      "maximum ports in rule before demotion to any-any port group" },

    { "bleedover_warnings_enabled", Parameter::PT_BOOL, nullptr, "false",
      "print warning if a rule is demoted to any-any port group" },

    { "enable_single_rule_group", Parameter::PT_BOOL, nullptr, "false",
      "put all rules into one group" },

    { "debug", Parameter::PT_BOOL, nullptr, "false",
      "print verbose fast pattern info" },

    { "debug_print_nocontent_rule_tests", Parameter::PT_BOOL, nullptr, "false",
      "print rule group info during packet evaluation" },

    { "debug_print_rule_group_build_details", Parameter::PT_BOOL, nullptr, "false",
      "print rule group info during compilation" },

    { "debug_print_rule_groups_uncompiled", Parameter::PT_BOOL, nullptr, "false",
      "prints uncompiled rule group information" },

    { "debug_print_rule_groups_compiled", Parameter::PT_BOOL, nullptr, "false",
      "prints compiled rule group information" },

    { "debug_print_fast_pattern", Parameter::PT_BOOL, nullptr, "false",
      "print fast pattern info for each rule" },

    { "max_pattern_len", Parameter::PT_INT, "0:", "0",
      "truncate patterns when compiling into state machine (0 means no maximum)" },

    { "max_queue_events", Parameter::PT_INT, nullptr, "5",
      "maximum number of matching fast pattern states to queue per packet" },

    { "no_stream_inserts", Parameter::PT_BOOL, nullptr, "false",
      "don't inspect reassembled payload - good for performance, bad for detection" },

    { "search_method", Parameter::PT_STRING, nullptr, "ac_bnfa_q",
      "set fast pattern algorithm - choose available search engine" },

    { "split_any_any", Parameter::PT_BOOL, nullptr, "false",
      "evaluate any-any rules separately to save memory" },

    { "search_optimize", Parameter::PT_BOOL, nullptr, "false",
      "tweak state machine construction for better performance" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SearchEngineModule : public Module
{
public:
    SearchEngineModule() : Module("search_engine", search_engine_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool SearchEngineModule::set(const char*, Value& v, SnortConfig* sc)
{
    FastPatternConfig* fp = sc->fast_pattern_config;

    if ( v.is("bleedover_port_limit") )
        fpDetectSetBleedOverPortLimit(fp, v.get_long());

    else if ( v.is("bleedover_warnings_enabled") )
    {
        if ( v.get_bool() )
            fpDetectSetBleedOverWarnings(fp);  // FIXIT these should take arg
    }
    else if ( v.is("enable_single_rule_group") )
    {
        if ( v.get_bool() )
            fpDetectSetSingleRuleGroup(fp);
    }
    else if ( v.is("debug") )
    {
        if ( v.get_bool() )
            fpSetDebugMode(fp);
    }
    else if ( v.is("debug_print_nocontent_rule_tests") )
    {
        if ( v.get_bool() )
            fpDetectSetDebugPrintNcRules(fp);
    }
    else if ( v.is("debug_print_rule_group_build_details") )
    {
        if ( v.get_bool() )
            fpDetectSetDebugPrintRuleGroupBuildDetails(fp);
    }
    else if ( v.is("debug_print_rule_groups_uncompiled") )
    {
        if ( v.get_bool() )
            fpDetectSetDebugPrintRuleGroupsUnCompiled(fp);
    }
    else if ( v.is("debug_print_rule_groups_compiled") )
    {
        if ( v.get_bool() )
            fpDetectSetDebugPrintRuleGroupsCompiled(fp);
    }
    else if ( v.is("debug_print_fast_pattern") )
        fpDetectSetDebugPrintFastPatterns(fp, v.get_bool());

    else if ( v.is("max_pattern_len") )
        fpSetMaxPatternLen(fp, v.get_long());

    else if ( v.is("max_queue_events") )
        fpSetMaxQueueEvents(fp, v.get_long());

    else if ( v.is("no_stream_inserts") )
        fpSetStreamInsert(fp);

    else if ( v.is("search_method") )
    {
        if ( fpSetDetectSearchMethod(fp, v.get_string()) )
            return false;
    }
    else if ( v.is("split_any_any") )
        fpDetectSetSplitAnyAny(fp, v.get_long());

    else if ( v.is("search_optimize") )
        fpSetDetectSearchOpt(fp, v.get_long());

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// profile module
//-------------------------------------------------------------------------

#ifdef PERF_PROFILING
static const Parameter profile_file_params[] =
{
    { "name", Parameter::PT_STRING, "128", nullptr,
      "output to file instead of log" },

    { "append", Parameter::PT_BOOL, nullptr, "false",
      "append or overwrite" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profile_rule_params[] =
{
    { "count", Parameter::PT_INT, "-1:", "-1",
      "print results to given level (-1 = all, 0 = off?)" },

    { "sort", Parameter::PT_ENUM, 
      "checks | avg_ticks | total_ticks | matches | no_matches | "
      "avg_ticks_per_match | avg_ticks_per_no_match",
      "avg_ticks", "sort by given field" },

    { "file", Parameter::PT_TABLE, profile_file_params, nullptr,
      "file config" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profile_preproc_params[] =
{
    { "count", Parameter::PT_INT, "-1:", "-1",
      "print results to given level (-1 = all, 0 = off?)" },

    { "sort", Parameter::PT_ENUM,
      "checks | avg_ticks | total_ticks", "avg_ticks",
      "sort by given field" },

    { "file", Parameter::PT_TABLE, profile_file_params, nullptr,
      "file config" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profile_params[] =
{
    { "rules", Parameter::PT_TABLE, profile_rule_params, nullptr,
      "" },

    { "preprocs", Parameter::PT_TABLE, profile_preproc_params, nullptr,
      "" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ProfileModule : public Module
{
public:
    ProfileModule() : Module("profile", profile_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool ProfileModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    ProfileConfig* p;
    const char* spr = "profile.rules";
    const char* spp = "profile.preprocs";

    if ( !strncmp(fqn, spr, strlen(spr)) )
        p = &sc->profile_rules;

    else if ( !strncmp(fqn, spp, strlen(spp)) )
        p = &sc->profile_preprocs;

    else
        return false;

    if ( v.is("count") )
        p->num = v.get_long();

    else if ( v.is("sort") )
        p->sort = v.get_long() + 1;

    else if ( v.is("append") )
        p->append = v.get_long() + 1;

    else if ( v.is("name") )
        p->filename = SnortStrdup(v.get_string());  // FIXIT use c++ string
        // FIXIT do this after log dir is set
        //p->filename = ProcessFileOption(sc, v.get_string());

    else
        return false;

    return true;
}
#endif

//-------------------------------------------------------------------------
// classification module
//-------------------------------------------------------------------------
// FIXIT signature.{h,cc} has type and name confused
// the keys here make more sense

static const Parameter classification_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "name used with classtype rule option" },

    { "priority", Parameter::PT_INT, "0:", "1",
      "default priority for class" },

    { "text", Parameter::PT_STRING, nullptr, nullptr,
      "description of class" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ClassificationsModule : public Module
{
public:
    ClassificationsModule() : 
        Module("classifications", classification_params, true) { };

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

private:
    string name;
    string text;
    int priority;
};

bool ClassificationsModule::begin(const char*, int, SnortConfig*)
{
    name.erase();
    text.erase();
    priority = 1;
    return true;
}

bool ClassificationsModule::end(const char*, int idx, SnortConfig* sc)
{
    if ( idx )
        AddClassification(sc, name.c_str(), text.c_str(), priority);
    return true;
}

bool ClassificationsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("name") )
        name = v.get_string();

    else if ( v.is("priority") )
        priority = v.get_long();

    else if ( v.is("text") )
        text = v.get_string();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// reference module
//-------------------------------------------------------------------------
// FIXIT signature.{h,cc} has type and name confused
// the keys here make more sense

static const Parameter reference_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "name used with classtype rule option" },

    { "url", Parameter::PT_STRING, nullptr, nullptr,
      "where this reference is defined" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ReferencesModule : public Module
{
public:
    ReferencesModule() : 
        Module("references", reference_params, true) { };

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

private:
    string name;
    string url;
};

bool ReferencesModule::begin(const char*, int, SnortConfig*)
{
    name.erase();
    url.erase();
    return true;
}

bool ReferencesModule::end(const char*, int idx, SnortConfig* sc)
{
    if ( idx )
        ReferenceSystemAdd(sc, name.c_str(), url.c_str());
    return true;
}

bool ReferencesModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("name") )
        name = v.get_string();

    else if ( v.is("url") )
        url = v.get_string();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// alerts module
//-------------------------------------------------------------------------

static const Parameter alerts_params[] =
{
    { "alert_file", Parameter::PT_STRING, nullptr, nullptr,
      "set the alert output file name (FIXIT delete if not used)" },

    { "alert_with_interface_name", Parameter::PT_BOOL, nullptr, "false",
      "include interface in alert info (fast, full, or syslog only)" },

    { "default_rule_state", Parameter::PT_BOOL, nullptr, "true",
      "enable or disable ips rules" },

    { "detection_filter_memcap", Parameter::PT_INT, "0:", "1048576",
      "set available memory for filters" },

    { "event_filter_memcap", Parameter::PT_INT, "0:", "1048576",
      "set available memory for filters" },

    { "flowbits_size", Parameter::PT_INT, "0:2048", "1024",
      "maximum number of allowed unique flowbits" },

    { "order", Parameter::PT_STRING, nullptr, "pass drop alert log",
      "change the order of rule action application" },

    { "rate_filter_memcap", Parameter::PT_INT, "0:", "1048576",
      "set available memory for filters" },

    { "reference_net", Parameter::PT_STRING, nullptr, "",
      "set the CIDR for homenet "
      "(for use with -l or -B, does NOT change $HOME_NET in IDS mode)"
    },

    { "stateful", Parameter::PT_BOOL, nullptr, "false",
      "don't alert w/o established session (note: rule action still taken)" },

    { "tunnel_verdicts", Parameter::PT_STRING, nullptr, nullptr,
      "let DAQ handle non-allow verdicts for GTP|Teredo|6in4|4in6 traffic" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class AlertsModule : public Module
{
public:
    AlertsModule() : Module("alerts", alerts_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool AlertsModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("alert_file") )
        sc->alert_file = SnortStrdup(v.get_string());

    else if ( v.is("alert_with_interface_name") )
        sc->output_flags |= OUTPUT_FLAG__ALERT_IFACE;

    else if ( v.is("default_rule_state") )
        sc->default_rule_state = v.get_long();

    else if ( v.is("detection_filter_memcap") )
        sc->detection_filter_config->memcap = v.get_long();

    else if ( v.is("event_filter_memcap") )
        sc->threshold_config->memcap = v.get_long();

    else if ( v.is("flowbits_size") )
    {
        setFlowbitSize(v.get_long());
        sc->flowbit_size = (uint16_t)getFlowbitSizeInBytes();
    }

    else if ( v.is("order") )
        OrderRuleLists(sc, v.get_string());

    else if ( v.is("rate_filter_memcap") )
        sc->rate_filter_config->memcap = v.get_long();

    else if ( v.is("reference_net") )
        return ( sfip_pton(v.get_string(), &sc->homenet) == SFIP_SUCCESS );

    else if ( v.is("stateful") )
        sc->run_flags |= RUN_FLAG__ASSURE_EST;

    else if ( v.is("tunnel_verdicts") )
        ConfigTunnelVerdicts(sc, v.get_string());

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// output module
//-------------------------------------------------------------------------

static const Parameter output_event_trace_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "where to write event trace logs" },

    { "max_data", Parameter::PT_INT, "0:65535", "0",
      "maximum amount of packet data to capture" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter output_params[] =
{
    { "dump_chars_only", Parameter::PT_BOOL, nullptr, "false",
      "turns on character dumps (same as -C)" },

    { "dump_payload", Parameter::PT_BOOL, nullptr, "false",
      "dumps application layer (same as -d)" },

    { "dump_payload_verbose", Parameter::PT_BOOL, nullptr, "false",
      "dumps raw packet starting at link layer (same as -X)" },

    { "log_ipv6_extra_data", Parameter::PT_BOOL, nullptr, "false",
      "log IPv6 source and destination addresses as unified2 extra data records" },

    { "event_trace", Parameter::PT_TABLE, output_event_trace_params, nullptr,
      "" },

    { "quiet", Parameter::PT_BOOL, nullptr, "false",
      "suppress non-fatal information (still show alerts, same as -q)" },

    { "logdir", Parameter::PT_STRING, nullptr, ".",
      "where to put log files (same as -l)" },

    { "nolog", Parameter::PT_BOOL, nullptr, "false",
      "turn off logging (alerts still work, same as -N)" },

    { "obfuscate", Parameter::PT_BOOL, nullptr, "false",
      "obfuscate the logged IP addresses (same as -O)" },

    { "show_year", Parameter::PT_BOOL, nullptr, "false",
      "include year in timestamp in the alert and log files (same as -y)" },

    { "tagged_packet_limit", Parameter::PT_INT, "0:", "256",
      "maximum number of packets tagged for non-packet metrics" },

    { "verbose", Parameter::PT_BOOL, nullptr, "false",
      "be verbose (same as -v)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class OutputModule : public Module
{
public:
    OutputModule() : Module("output", output_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool OutputModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("dump_chars_only") )
    {
        if ( v.get_bool() )
        sc->output_flags |= OUTPUT_FLAG__CHAR_DATA;
    }
    else if ( v.is("dump_payload") )
    {
        if ( v.get_bool() )
        sc->output_flags |= OUTPUT_FLAG__APP_DATA;
    }
    else if ( v.is("dump_payload_verbose") )
    {
        if ( v.get_bool() )
        sc->output_flags |= OUTPUT_FLAG__VERBOSE_DUMP;
    }
    else if ( v.is("file") )
        sc->event_trace_file = SnortStrdup(v.get_string());

    else if ( v.is("log_ipv6_extra_data") )
    {
        if ( v.get_bool() )
        sc->log_ipv6_extra = 1; // FIXIT move to output|logging_flags
    }
    else if ( v.is("quiet") )
    {
        if ( v.get_bool() )
        sc->logging_flags |= LOGGING_FLAG__QUIET;
    }
    else if ( v.is("logdir") )
        sc->log_dir = SnortStrdup(v.get_string());

    else if ( v.is("max_data") )
        sc->event_trace_max = v.get_long();

    else if ( v.is("nolog") )
    {
        if ( v.get_bool() )
            sc->output_flags |= OUTPUT_FLAG__NO_LOG;
    }
    else if ( v.is("obfuscate") )
    {
        if ( v.get_bool() )
        sc->output_flags |= OUTPUT_FLAG__OBFUSCATE;
    }
    else if ( v.is("show_year") )
    {
        if ( v.get_bool() )
        sc->output_flags |= OUTPUT_FLAG__INCLUDE_YEAR;
    }
    else if ( v.is("tagged_packet_limit") )
        sc->tagged_packet_limit = v.get_long();

    else if ( v.is("verbose") )
    {
        if ( v.get_bool() )
        sc->logging_flags |= LOGGING_FLAG__VERBOSE;
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// active module
//-------------------------------------------------------------------------

static const Parameter active_params[] =
{
    { "attempts", Parameter::PT_INT, "0:20", "0",
      "number of TCP packets sent per response (with varying sequence numbers)" },

    { "device", Parameter::PT_STRING, nullptr, nullptr,
      "use 'ip' for network layer responses or 'eth0' etc for link layer" },

    { "dst_mac", Parameter::PT_STRING, nullptr, nullptr,
      "use format '01:23:45:67:89:ab'" },

    { "max_responses", Parameter::PT_INT, "0:", "255",
      "maximum number of responses" },

    { "min_interval", Parameter::PT_INT, "1:", "255",
      "minimum number of seconds between responses" },

    { "react", Parameter::PT_STRING, nullptr, nullptr,
      "file containing HTTP reponse (headers and body)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ActiveModule : public Module
{
public:
    ActiveModule() : Module("active", active_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool ActiveModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("attempts") )
        sc->respond_attempts = v.get_long();

    else if ( v.is("device") )
        sc->respond_device = SnortStrdup(v.get_string());

    else if ( v.is("dst_mac") )
        ConfigDstMac(sc, v.get_string());

    else if ( v.is("max_responses") )
        sc->max_responses = v.get_long();

    else if ( v.is("min_interval") )
        sc->min_interval = v.get_long();

    else if ( v.is("react") )
        sc->react_page = SnortStrdup(v.get_string());

    return true;
}

//-------------------------------------------------------------------------
// packets module
//-------------------------------------------------------------------------

static const Parameter packets_params[] =
{
    { "bpf_file", Parameter::PT_STRING, nullptr, nullptr,
      "file with BPF to select traffic for Snort" },

    { "enable_inline_init_failopen", Parameter::PT_BOOL, nullptr, "true",
      "whether to pass traffic during later stage of initialization to avoid drops" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "maximum number of packets to process before stopping (0 is unlimited)" },

    { "skip", Parameter::PT_INT, "0:", "0",
      "number of packets to skip before before processing" },

    { "vlan_agnostic", Parameter::PT_BOOL, nullptr, "false",
      "determines whether VLAN info is used to track fragments and connections" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class PacketsModule : public Module
{
public:
    PacketsModule() : Module("packets", packets_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool PacketsModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("address_space_agnostic") )
        sc->addressspace_agnostic = v.get_long();

    else if ( v.is("bpf_file") )
        sc->bpf_file = SnortStrdup(v.get_string());

    else if ( v.is("enable_inline_init_failopen") )
    {
        if ( !v.get_bool() )
            sc->run_flags |= RUN_FLAG__DISABLE_FAILOPEN;
    }
    else if ( v.is("limit") )
        sc->pkt_cnt = v.get_long();

    else if ( v.is("skip") )
        sc->pkt_skip = v.get_long();

    else if ( v.is("vlan_agnostic") )
        sc->vlan_agnostic = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// daq module
//-------------------------------------------------------------------------

static const Parameter daq_params[] =
{
    // FIXIT should be a list?
    { "dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory where to search for DAQ plugins" },

    { "mode", Parameter::PT_SELECT, "passive | inline | read-file", nullptr,
      "set mode of operation" },

    { "no_promisc", Parameter::PT_BOOL, nullptr, "false",
      "whether to put DAQ device into promiscuous mode" },

    // FIXIT range determined by available plugins
    { "name", Parameter::PT_STRING, nullptr, "pcap",
      "select name of DAQ" },

    // FIXIT should be a list?
    { "var", Parameter::PT_STRING, nullptr, nullptr,
      "list of name=value DAQ-specific parameters" },

    { "snaplen", Parameter::PT_INT, "0:65535", "deflt",
      "set snap length (same as -P)" },

    { "decode_data_link", Parameter::PT_BOOL, nullptr, "false",
      "display the second layer header info" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class DaqModule : public Module
{
public:
    DaqModule() : Module("daq", daq_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool DaqModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("dir") )
        ConfigDaqDir(sc, v.get_string());

    else if ( v.is("mode") )
        ConfigDaqMode(sc, v.get_string());

    else if ( v.is("no_promisc") )
    {
        if ( v.get_bool() )
            sc->run_flags |= RUN_FLAG__NO_PROMISCUOUS;
    }
    else if ( v.is("name") )
        ConfigDaqType(sc, v.get_string());

    else if ( v.is("var") )
        ConfigDaqVar(sc, v.get_string());

    else if ( v.is("decode_data_link") )
    {
        if ( v.get_bool() )
            ConfigDecodeDataLink(sc, "");
    }
    else if ( v.is("snaplen") )
        ConfigPacketSnaplen(sc, v.get_string());

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// attribute_table module
//-------------------------------------------------------------------------

static const Parameter attribute_table_params[] =
{
    { "max_hosts", Parameter::PT_INT, "32:207551", "0",
      "maximum number of hosts in attribute table" },

    { "max_services_per_host", Parameter::PT_INT, "1:65535", "0",
      "maximum number of services per host entry in attribute table" },

    { "max_metadata_services", Parameter::PT_INT, "1:256", "0",
      "max" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class AttributeTableModule : public Module
{
public:
    AttributeTableModule() : Module("attribute_table", attribute_table_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool AttributeTableModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("max_hosts") )
        sc->max_attribute_hosts = v.get_long();

    else if ( v.is("max_services_per_host") )
        sc->max_attribute_services_per_host = v.get_long();

    else if ( v.is("max_metadata_services") )
        sc->max_metadata_services = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// network module
//-------------------------------------------------------------------------

static const Parameter network_params[] =
{
    { "checksum_drop", Parameter::PT_MULTI,
      "all | noip | notcp | noudp | noicmp | none", "none",
      "drop if checksum is bad" },

    { "checksum_eval", Parameter::PT_MULTI, 
      "all | noip | notcp | noudp | noicmp | none", "all",
      "checksums to verify" },

    { "decode_drops", Parameter::PT_BOOL, nullptr, "false",
      "enable dropping of packets by the decoder" },

    { "id", Parameter::PT_INT, "0:65535", "0",
      "correlate unified2 events with configuration" },

    { "min_ttl", Parameter::PT_INT, "1:255", "1",
      "alert / normalize packets with lower ttl / hop limit "
      "(you must enable rules and / or normalization also)" },

    { "new_ttl", Parameter::PT_INT, "1:255", "1",
      "use this value for responses and when normalizing" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class NetworkModule : public Module
{
public:
    NetworkModule() : Module("network", network_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool NetworkModule::set(const char*, Value& v, SnortConfig* sc)
{
    NetworkPolicy* p = get_network_policy();

    if ( v.is("checksum_drop") )
        ConfigChecksumDrop(sc, v.get_string());

    else if ( v.is("checksum_eval") )
        ConfigChecksumMode(sc, v.get_string());

    else if ( v.is("decode_drops") )
        p->decoder_drop = v.get_bool();

    else if ( v.is("id") )
        p->user_policy_id = v.get_long();

    else if ( v.is("min_ttl") )
        p->min_ttl = (uint8_t)v.get_long();

    else if ( v.is("new_ttl") )
        p->new_ttl = (uint8_t)v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// detection policy module
//-------------------------------------------------------------------------

static const Parameter ips_params[] =
{
    { "enable_builtin_rules", Parameter::PT_BOOL, nullptr, "false",
      "enable events from builtin rules w/o stubs" },

    { "id", Parameter::PT_INT, "0:65535", "0",
      "correlate unified2 events with configuration" },

    { "include", Parameter::PT_STRING, nullptr, nullptr,
      "snort-classic rules and includes" },

    { "mode", Parameter::PT_ENUM, "tap | inline | inline-test", "tap",
      "set policy mode" },

    { "rules", Parameter::PT_STRING, nullptr, nullptr,
      "snort rules and includes" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class IpsModule : public Module
{
public:
    IpsModule() : Module("ips", ips_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool IpsModule::set(const char*, Value& v, SnortConfig*)
{
    IpsPolicy* p = snort_conf->get_ips_policy();

    if ( v.is("enable_builtin_rules") )
        p->enable_builtin_rules = v.get_bool();

    else if ( v.is("id") )
        p->user_policy_id = v.get_long();

    else if ( v.is("include") )
        p->include = v.get_string();

    else if ( v.is("mode") )
        p->policy_mode = GetPolicyMode((PolicyMode)v.get_long());

    else if ( v.is("rules") )
        p->rules = v.get_string();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// process module
//-------------------------------------------------------------------------

static const Parameter process_params[] =
{
    { "chroot", Parameter::PT_STRING, nullptr, nullptr,
      "set chroot directory (same as -t)" },

    { "daemon", Parameter::PT_BOOL, nullptr, "false",
      "fork as a daemon (same as -D)" },

    { "dirty_pig", Parameter::PT_BOOL, nullptr, "false",
      "shutdown without internal cleanup" },

    { "set_gid", Parameter::PT_STRING, nullptr, nullptr,
      "set group ID (same as -g)" },

    { "set_uid", Parameter::PT_STRING, nullptr, nullptr,
      "set user ID (same as -u)" },

    { "plugin_path", Parameter::PT_STRING, nullptr, nullptr,
      "directory containing plugins (same as --plugin-path)" },

    { "script_path", Parameter::PT_STRING, nullptr, nullptr,
      "directory containing scripts (same as --scripts-path)" },

    { "umask", Parameter::PT_STRING, nullptr, nullptr,
      "set process umask (same as -m)" },

    { "utc", Parameter::PT_BOOL, nullptr, "false",
      "use UTC instead of local time for timestamps" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ProcessModule : public Module
{
public:
    ProcessModule() : Module("process", process_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool ProcessModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("daemon") )
    {
        if ( v.get_bool() )
            ConfigDaemon(sc, "");
    }
    else if ( v.is("chroot") )
        ConfigChrootDir(sc, v.get_string());

    else if ( v.is("dirty_pig") )
    {
        if ( v.get_bool() )
            ConfigDirtyPig(sc, "");
    }
    else if ( v.is("set_gid") )
        ConfigSetGid(sc, v.get_string());

    else if ( v.is("set_uid") )
        ConfigSetUid(sc, v.get_string());

    else if ( v.is("plugin_path") )
        ConfigPluginPath(sc, v.get_string());

    else if ( v.is("script_path") )
        ConfigScriptPath(sc, v.get_string());

    else if ( v.is("umask") )
        ConfigUmask(sc, v.get_string());

    else if ( v.is("utc") )
    {
        if ( v.get_bool() )
            ConfigUtc(sc, "");
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// vars module
//-------------------------------------------------------------------------
// FIXIT signature.{h,cc} has type and name confused
// the keys here make more sense

static const Parameter vars_params[] =
{
    { nullptr, Parameter::PT_STRING, nullptr, nullptr,
      "port, ip, or path variable" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class VarsModule : public Module
{
public:
    VarsModule() : 
        Module("vars", vars_params, true) { };

    bool set(const char*, Value&, SnortConfig*);
};

#include <iostream>
bool VarsModule::set(const char* fqn, Value& v, SnortConfig*)
{
    cout << fqn << " = " << v.get_name() << endl;

    return true;
}

//-------------------------------------------------------------------------
// file_id module
//-------------------------------------------------------------------------

static const Parameter file_id_params[] =
{
    { "type_depth", Parameter::PT_INT, "0:", "1460",
      "stop type ID at this point" },

    { "signature_depth", Parameter::PT_INT, "0:", "10485760",
      "stop signature at this point" },

    { "block_timeout", Parameter::PT_INT, "0:", "86400",
      "stop blocking after this many seconds" },

    { "lookup_timeout", Parameter::PT_INT, "0:", "2",
      "give up on lookup after this many seconds" },

    { "block_timeout_lookup", Parameter::PT_BOOL, nullptr, "false",
      "block if lookup times out" },

#if defined(DEBUG_MSGS) || defined (REG_TEST)
    { "enable_type", Parameter::PT_BOOL, nullptr, "false",
      "enable type ID" },

    { "enable_signature", Parameter::PT_BOOL, nullptr, "false",
      "enable signature calculation" },

    { "show_data_depth", Parameter::PT_INT, "0:", "100",
      "print this many octets" },
#endif
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class FileIdModule : public Module
{
public:
    FileIdModule() : Module("file_id", file_id_params) { };
    bool set(const char*, Value&, SnortConfig*);
};

bool FileIdModule::set(const char*, Value& v, SnortConfig* sc)
{
    FileConfig* fc = get_file_config(&sc->file_config);
    assert(fc);

    if ( v.is("type_depth") )
        fc->file_type_depth = v.get_long();

    else if ( v.is("signature_depth") )
        fc->file_signature_depth = v.get_long();

    else if ( v.is("block_timeout") )
        fc->file_block_timeout = v.get_long();

    else if ( v.is("lookup_timeout") )
        fc->file_lookup_timeout = v.get_long();

    else if ( v.is("block_timeout_lookup") )
        fc->block_timeout_lookup = v.get_bool();

#if defined(DEBUG_MSGS) || defined (REG_TEST)
    else if ( v.is("enable_type") )
        file_api->enable_file_type(nullptr);

    else if ( v.is("enable_signature") )
        file_api->enable_file_signature(nullptr);

    else if ( v.is("show_data_depth") )
        fc->show_data_depth = v.get_long();
#endif
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// suppress module
//-------------------------------------------------------------------------

static const Parameter suppress_params[] =
{
    { "gid", Parameter::PT_INT, "0:", "0",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "0:", "0",
      "rule signature ID" },

    { "track", Parameter::PT_ENUM, "by_src | by_dst", nullptr,
      "suppress only matching source or destination addresses" },

    { "ip", Parameter::PT_STRING, nullptr, nullptr,
      "restrict suppression to these addresses according to track" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SuppressModule : public Module
{
public:
    SuppressModule() : Module("suppress", suppress_params, true) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

private:
    THDX_STRUCT thdx;
};

bool SuppressModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("gid") )
        thdx.gen_id = v.get_long();

    else if ( v.is("sid") )
        thdx.sig_id = v.get_long();

    else if ( v.is("track") )
        thdx.tracking = v.get_long() + 1;

    else if ( v.is("ip") )
        thdx.ip_address = sfip_var_from_string(v.get_string());

    else
        return false;

    return true;
}

bool SuppressModule::begin(const char*, int, SnortConfig*)
{
    memset(&thdx, 0, sizeof(thdx));
    thdx.type = THD_TYPE_SUPPRESS;
    thdx.priority = THD_PRIORITY_SUPPRESS;
    thdx.tracking = THD_TRK_NONE;
    return true;
}

bool SuppressModule::end(const char*, int idx, SnortConfig* sc)
{
    if ( idx && sfthreshold_create(sc, sc->threshold_config, &thdx) )
        return false;

    return true;
}

//-------------------------------------------------------------------------
// event_filter module
//-------------------------------------------------------------------------

static const Parameter event_filter_params[] =
{
    { "gid", Parameter::PT_INT, "0:", "0",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "0:", "0",
      "rule signature ID" },

    { "type", Parameter::PT_ENUM, "limit | threshold | both", nullptr,
      "1st count events | every count events | once after count events" },

    { "track", Parameter::PT_ENUM, "by_src | by_dst", nullptr,
      "filter only matching source or destination addresses" },

    { "count", Parameter::PT_INT, "0:", "0",
      "number of events in interval before tripping" },

    { "seconds", Parameter::PT_INT, "0:", "0",
      "count interval" },

    { "ip", Parameter::PT_STRING, nullptr, nullptr,
      "restrict filter to these addresses according to track" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class EventFilterModule : public Module
{
public:
    EventFilterModule() : Module("event_filter", event_filter_params, true) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

private:
    THDX_STRUCT thdx;
};

bool EventFilterModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("gid") )
        thdx.gen_id = v.get_long();

    else if ( v.is("sid") )
        thdx.sig_id = v.get_long();

    else if ( v.is("track") )
        thdx.tracking = v.get_long() + 1;

    else if ( v.is("ip") )
        thdx.ip_address = sfip_var_from_string(v.get_string());

    else if ( v.is("count") )
        thdx.count = v.get_long();

    else if ( v.is("seconds") )
        thdx.seconds = v.get_long();

    else if ( v.is("type") )
        thdx.type = v.get_long();

    else
        return false;

    return true;
}

bool EventFilterModule::begin(const char*, int, SnortConfig*)
{
    memset(&thdx, 0, sizeof(thdx));
    thdx.priority = THD_PRIORITY_SUPPRESS;
    thdx.tracking = THD_TRK_NONE;
    return true;
}

bool EventFilterModule::end(const char*, int idx, SnortConfig* sc)
{
    if ( idx && sfthreshold_create(sc, sc->threshold_config, &thdx) )
    {
        LogMessage("ERROR: bad event_filter gid = %u, sid = %u",
            thdx.gen_id, thdx.sig_id);
        return false;
    }
    return true;
}

//-------------------------------------------------------------------------
// rate_filter module
//-------------------------------------------------------------------------

static const Parameter rate_filter_params[] =
{
    { "gid", Parameter::PT_INT, "0:", "0",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "0:", "0",
      "rule signature ID" },

    { "track", Parameter::PT_ENUM, "by_src | by_dst | by_rule", nullptr,
      "filter only matching source or destination addresses" },

    { "count", Parameter::PT_INT, "0:", "0",
      "number of events in interval before tripping" },

    { "seconds", Parameter::PT_INT, "0:", "0",
      "count interval" },

    { "new_action", Parameter::PT_SELECT,
      // FIXIT range based on available action plugins
      "alert | drop | log | pass | | reject | sdrop", "alert",
      "restrict filter to these addresses according to track" },

    { "timeout", Parameter::PT_INT, "0:", "1",
      "count interval" },

    { "apply_to", Parameter::PT_STRING, nullptr, nullptr,
      "restrict filter to these addresses according to track" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RateFilterModule : public Module
{
public:
    RateFilterModule() : Module("rate_filter", rate_filter_params, true) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

private:
    tSFRFConfigNode thdx;
};

bool RateFilterModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("gid") )
        thdx.gid = v.get_long();

    else if ( v.is("sid") )
        thdx.sid = v.get_long();

    else if ( v.is("track") )
        thdx.tracking = (SFRF_TRACK)(v.get_long() + 1);

    else if ( v.is("count") )
        thdx.count = v.get_long();

    else if ( v.is("seconds") )
        thdx.seconds = v.get_long();

    else if ( v.is("timeout") )
        thdx.timeout = v.get_long();

    else if ( v.is("apply_to") )
        thdx.applyTo = sfip_var_from_string(v.get_string());

    else if ( v.is("new_action") )
        thdx.newAction = (RuleType)(v.get_long() + 1);

    else
        return false;

    return true;
}

bool RateFilterModule::begin(const char*, int, SnortConfig*)
{
    memset(&thdx, 0, sizeof(thdx));
    return true;
}

bool RateFilterModule::end(const char*, int idx, SnortConfig* sc)
{
    if ( idx && RateFilter_Create(sc, sc->rate_filter_config,  &thdx) )
        return false;

    return true;
}

//-------------------------------------------------------------------------
// rule_state module
//-------------------------------------------------------------------------

static const Parameter rule_state_params[] =
{
    { "gid", Parameter::PT_INT, "0:", "0",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "0:", "0",
      "rule signature ID" },

    { "enable", Parameter::PT_BOOL, nullptr, "true",
      "enable or disable rule in all policies" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RuleStateModule : public Module
{
public:
    RuleStateModule() : Module("rule_state", rule_state_params) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

private:
    RuleState state;
};

bool RuleStateModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("gid") )
        state.gid = v.get_long();

    else if ( v.is("sid") )
        state.sid = v.get_long();

    else if ( v.is("enable") )
        state.state = v.get_bool();

    else
        return false;

    return true;
}

bool RuleStateModule::begin(const char*, int, SnortConfig*)
{
    memset(&state, 0, sizeof(state));
    return true;
}

bool RuleStateModule::end(const char*, int idx, SnortConfig* sc)
{
    if ( idx )
        AddRuleState(sc, state);
    return true;
}

//-------------------------------------------------------------------------
// snort module
//-------------------------------------------------------------------------

static const Parameter snort_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command snort_cmds[] =
{
    { "show_plugins", main_dump_plugins, "show available plugins" },
    { "dump_stats", main_dump_stats, "show summary statistics" },
    { "rotate_stats", main_rotate_stats, "roll perfmonitor log files" },
    { "reload_config", main_reload_config, "load new configuration" },
    { "reload_attributes", main_reload_attributes, "load a new hosts.xml" },
    { "process", main_process, "process given pcap" },
    { "pause", main_pause, "suspend packet processing" },
    { "resume", main_resume, "continue packet processing" },
    { "quit", main_quit, "shutdown and dump-stats" },
    { "help", main_help, "this output" },
    { nullptr, nullptr, nullptr }
};

class SnortModule : public Module
{
public:
    SnortModule() : Module("snort", snort_params, snort_cmds) { };
    bool set(const char*, Value&, SnortConfig*) { return false; };
};

//-------------------------------------------------------------------------
// hosts module
//-------------------------------------------------------------------------

// FIXIT these are cloned from ip_module.cc and tcp_module.cc

static const char* ip_policies =
    "first | linux | bsd | bsd_right |last | windows | solaris";

static const char* tcp_policies =
    "first | last | bsd | linux | old-linux | windows | win-2003 | vista "
    "solaris | hpux | hpux10 | irix | macos";

static const Parameter service_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "service identifier" },

    { "proto", Parameter::PT_ENUM, "tcp | udp", "tcp",
      "ip protocol" },

    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port number" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter hosts_params[] =
{
    { "ip", Parameter::PT_ADDR, nullptr, nullptr,
      "hosts address / cidr" },

    { "frag_policy", Parameter::PT_ENUM, ip_policies, "linux",
      "defragmentation policy" },

    { "tcp_policy", Parameter::PT_ENUM, tcp_policies, "linux",
      "tcp reassembly policy" },

    { "services", Parameter::PT_LIST, service_params, nullptr,
      "list of service parameters" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class HostsModule : public Module
{
public:
    HostsModule() : Module("hosts", hosts_params, true) { };
    ~HostsModule() { assert(!host && !app); };

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

private:
    ApplicationEntry* app;
    HostAttributeEntry* host;
};

bool HostsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("ip") )
        v.get_addr(host->ipAddr);

    else if ( v.is("frag_policy") )
    {
        strncpy(host->hostInfo.fragPolicyName, v.get_string(),
            sizeof(host->hostInfo.fragPolicyName));
        host->hostInfo.fragPolicy = v.get_long() + 1;
    }
    else if ( v.is("tcp_policy") )
    {
        strncpy(host->hostInfo.streamPolicyName, v.get_string(),
            sizeof(host->hostInfo.streamPolicyName));
        host->hostInfo.streamPolicy = v.get_long() + 1;
    }
    else if ( v.is("name") )
        app->protocol = AddProtocolReference(v.get_string());

    else if ( v.is("proto") )
        app->ipproto = AddProtocolReference(v.get_string());

    else if ( v.is("port") )
        app->port = v.get_long();

    else
        return false;

    return true;
}

bool HostsModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "hosts.services") )
        app = SFAT_CreateApplicationEntry();

    else if ( idx && !strcmp(fqn, "hosts") )
        host = SFAT_CreateHostEntry();

    else
        return false;

    return true;
}

bool HostsModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "hosts.services") )
    {
        SFAT_AddService(host, app);
        app = nullptr;
    }
    else if ( idx && !strcmp(fqn, "hosts") )
    {
        SFAT_AddHost(host);
        host = nullptr;
    }
    else
        return false;

    return true;
}

#if 0
//-------------------------------------------------------------------------
// xxx module - used as copy/paste template
//-------------------------------------------------------------------------

static const Parameter xxx_params[] =
{
    { "name", Parameter::PT_INT, "range", "deflt",
      "help" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap xxx_rules[] =
{
    { SID, "STR" },
    { 0, 0, nullptr }
};

class XXXModule : public Module
{
public:
    XXXModule() : Module("xxx", xxx_params, xxx_rules) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);
};

bool XXXModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("name") )
        sc->pkt_cnt = v.get_long();

    else
        return false;

    return true;
}

bool XXXModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool XXXModule::end(const char*, int, SnortConfig*)
{
    return true;
}

#endif
//-------------------------------------------------------------------------
// module manager stuff - move to framework/module_manager.cc
//-------------------------------------------------------------------------

void module_init()
{
    // FIXIT in alpha order for --help-config but module 
    // manager should sort anyway
    //
    // make sure parameters can be set regardless of sequence
    // since Lua calls this by table hash key traversal
    // (which is effectively random)
    // so module interdependencies must come after this phase
    //
    // this module is special :)
    ModuleManager::add_module(new SnortModule);

    // these modules are not policy specific
    ModuleManager::add_module(new ClassificationsModule);
    ModuleManager::add_module(new DaqModule);
    ModuleManager::add_module(new DetectionModule);
    ModuleManager::add_module(new PacketsModule);
    ModuleManager::add_module(new ProcessModule);
    ModuleManager::add_module(new ProfileModule);
    ModuleManager::add_module(new ReferencesModule);
    ModuleManager::add_module(new RuleStateModule);
    ModuleManager::add_module(new SearchEngineModule);

    // these could but prolly shouldn't be policy specific
    // or should be broken into policy and non-policy parts
    ModuleManager::add_module(new AlertsModule);
    ModuleManager::add_module(new EventQueueModule);
    ModuleManager::add_module(new OutputModule);

    // these modules could be in traffic policy
    ModuleManager::add_module(new ActiveModule);
    ModuleManager::add_module(new FileIdModule);

#ifdef PPM_MGR
    ModuleManager::add_module(new PpmModule);
#endif

    // these modules should be in ips policy
    ModuleManager::add_module(new EventFilterModule);
    ModuleManager::add_module(new RateFilterModule);
    ModuleManager::add_module(new SuppressModule);
    ModuleManager::add_module(new VarsModule);

    // these are preliminary policies
    ModuleManager::add_module(new NetworkModule);
    ModuleManager::add_module(new IpsModule);

    // these modules replace config and hosts.xml
    ModuleManager::add_module(new AttributeTableModule);
    ModuleManager::add_module(new HostsModule);
}

