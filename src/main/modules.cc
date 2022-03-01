//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// modules.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modules.h"

#include <sys/resource.h>

#include "codecs/codec_module.h"
#include "detection/detection_module.h"
#include "detection/fp_config.h"
#include "detection/rules.h"
#include "detection/tag.h"
#include "file_api/file_service.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/sfthd.h"
#include "filters/sfthreshold.h"
#include "flow/ha_module.h"
#include "framework/file_policy.h"
#include "framework/module.h"
#include "host_tracker/host_tracker_module.h"
#include "host_tracker/host_cache_module.h"
#include "latency/latency_module.h"
#include "log/messages.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "memory/memory_module.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq_module.h"
#include "packet_tracer/packet_tracer_module.h"
#include "parser/config_file.h"
#include "parser/parse_conf.h"
#include "parser/parse_ip.h"
#include "parser/parser.h"
#include "parser/vars.h"
#include "payload_injector/payload_injector_module.h"
#include "profiler/profiler.h"
#include "search_engines/pat_stats.h"
#include "side_channel/side_channel_module.h"
#include "sfip/sf_ipvar.h"
#include "stream/stream.h"
#include "target_based/host_attributes.h"
#include "target_based/snort_protocols.h"
#include "trace/trace_module.h"

#include "snort_config.h"
#include "snort_module.h"
#include "thread_config.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// event queue module
//-------------------------------------------------------------------------

static const Parameter event_queue_params[] =
{
    { "max_queue", Parameter::PT_INT, "1:max32", "8",
      "maximum events to queue" },

    { "log", Parameter::PT_INT, "1:max32", "3",
      "maximum events to log" },

    { "order_events", Parameter::PT_ENUM,
      "priority|content_length", "content_length",
      "criteria for ordering incoming events" },

    { "process_all_events", Parameter::PT_BOOL, nullptr, "false",
      "process just first action group or all action groups" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define event_queue_help \
    "configure event queue parameters"

class EventQueueModule : public Module
{
public:
    EventQueueModule() : Module("event_queue", event_queue_help, event_queue_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }
};

bool EventQueueModule::set(const char*, Value& v, SnortConfig* sc)
{
    EventQueueConfig* eq = sc->event_queue_config;

    if ( v.is("max_queue") )
        eq->max_events = v.get_uint32();

    else if ( v.is("log") )
        eq->log_events = v.get_uint32();

    else if ( v.is("order_events") )
    {
        if ( v.get_uint8() )
            eq->order = SNORT_EVENTQ_CONTENT_LEN;
        else
            eq->order = SNORT_EVENTQ_PRIORITY;
    }
    else if ( v.is("process_all_events") )
        eq->process_all_events = v.get_bool();

    return true;
}

bool EventQueueModule::end(const char*, int, SnortConfig* sc)
{
    EventQueueConfig* eq = sc->event_queue_config;

    if ( eq->max_events < eq->log_events )
        eq->max_events = eq->log_events;

    return true;
}

//-------------------------------------------------------------------------
// search engine module
//-------------------------------------------------------------------------

function<const char*()> get_search_methods = []()
{ return PluginManager::get_available_plugins(PT_SEARCH_ENGINE); };

static const Parameter search_engine_params[] =
{
    { "bleedover_port_limit", Parameter::PT_INT, "1:max32", "1024",
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

    { "max_pattern_len", Parameter::PT_INT, "0:max32", "0",
      "truncate patterns when compiling into state machine (0 means no maximum)" },

    { "max_queue_events", Parameter::PT_INT, "2:100", "5",  // upper bound is MAX_EVENT_MATCH
      "maximum number of matching fast pattern states to queue per packet" },

    { "detect_raw_tcp", Parameter::PT_BOOL, nullptr, "false",
      "detect on TCP payload before reassembly" },

    { "search_method", Parameter::PT_DYNAMIC, (void*)&get_search_methods, "ac_bnfa",
      "set fast pattern algorithm - choose available search engine" },

    { "offload_search_method", Parameter::PT_DYNAMIC, (void*)&get_search_methods, nullptr,
      "set fast pattern offload algorithm - choose available search engine" },

    { "rule_db_dir", Parameter::PT_STRING, nullptr, nullptr,
      "deserialize rule databases from given directory" },

    { "search_optimize", Parameter::PT_BOOL, nullptr, "true",
      "tweak state machine construction for better performance" },

    { "show_fast_patterns", Parameter::PT_BOOL, nullptr, "false",
      "print fast pattern info for each rule" },

    { "split_any_any", Parameter::PT_BOOL, nullptr, "true",
      "evaluate any-any rules separately to save memory" },

    { "queue_limit", Parameter::PT_INT, "0:max32", "0",
      "maximum number of fast pattern matches to queue per packet (0 is unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define search_engine_help \
    "configure fast pattern matcher"

namespace snort
{
THREAD_LOCAL PatMatQStat pmqs;
}

const PegInfo mpse_pegs[] =
{
    { CountType::MAX, "max_queued", "maximum fast pattern matches queued for further evaluation" },
    { CountType::SUM, "total_flushed", "total fast pattern matches processed" },
    { CountType::SUM, "total_inserts", "total fast pattern hits" },
    { CountType::SUM, "total_overruns", "fast pattern matches discarded due to overflow" },
    { CountType::SUM, "total_unique", "total unique fast pattern hits" },
    { CountType::SUM, "non_qualified_events", "total non-qualified events" },
    { CountType::SUM, "qualified_events", "total qualified events" },
    { CountType::SUM, "searched_bytes", "total bytes searched" },
    { CountType::END, nullptr, nullptr }
};

class SearchEngineModule : public Module
{
public:
    SearchEngineModule() : Module("search_engine", search_engine_help, search_engine_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return mpse_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&pmqs; }

    Usage get_usage() const override
    { return GLOBAL; }
};

bool SearchEngineModule::set(const char*, Value& v, SnortConfig* sc)
{
    FastPatternConfig* fp = sc->fast_pattern_config;

    if ( v.is("bleedover_port_limit") )
        fp->set_bleed_over_port_limit(v.get_uint32());

    else if ( v.is("bleedover_warnings_enabled") )
    {
        if ( v.get_bool() )
            fp->set_bleed_over_warnings();  // FIXIT-L these should take arg
    }
    else if ( v.is("enable_single_rule_group") )
    {
        if ( v.get_bool() )
            fp->set_single_rule_group();
    }
    else if ( v.is("debug") )
    {
        if ( v.get_bool() )
            fp->set_debug_mode();
    }
    else if ( v.is("debug_print_nocontent_rule_tests") )
    {
        if ( v.get_bool() )
            fp->set_debug_print_nc_rules();
    }
    else if ( v.is("debug_print_rule_group_build_details") )
    {
        if ( v.get_bool() )
            fp->set_debug_print_rule_group_build_details();
    }
    else if ( v.is("debug_print_rule_groups_uncompiled") )
    {
        if ( v.get_bool() )
            fp->set_debug_print_rule_groups_uncompiled();
    }
    else if ( v.is("debug_print_rule_groups_compiled") )
    {
        if ( v.get_bool() )
            fp->set_debug_print_rule_groups_compiled();
    }
    else if ( v.is("max_pattern_len") )
        fp->set_max_pattern_len(v.get_uint32());

    else if ( v.is("max_queue_events") )
        fp->set_max_queue_events(v.get_uint8());

    else if ( v.is("detect_raw_tcp") )
        fp->set_stream_insert(v.get_bool());

    else if ( v.is("rule_db_dir") )
        fp->set_rule_db_dir(v.get_string());

    else if ( v.is("search_method") )
    {
        if ( !fp->set_search_method(v.get_string()) )
            return false;
    }
    else if ( v.is("offload_search_method") )
    {
        if ( !fp->set_offload_search_method(v.get_string()) )
            return false;
    }
    else if ( v.is("search_optimize") )
        fp->set_search_opt(v.get_bool());

    else if ( v.is("show_fast_patterns") )
        fp->set_debug_print_fast_patterns(v.get_bool());

    else if ( v.is("split_any_any") )
        fp->set_split_any_any(v.get_bool());

    else if ( v.is("queue_limit") )
        fp->set_queue_limit(v.get_uint32());

    return true;
}

// -----------------------------------------------------------------------------
// profiler module
// -----------------------------------------------------------------------------

static const Parameter profiler_time_params[] =
{
    { "show", Parameter::PT_BOOL, nullptr, "true",
      "show module time profile stats" },

    { "count", Parameter::PT_INT, "0:max32", "0",
      "limit results to count items per level (0 = no limit)" },

    { "sort", Parameter::PT_ENUM,
      "none | checks | avg_check | total_time ",
      "total_time", "sort by given field" },

    { "max_depth", Parameter::PT_INT, "-1:255", "-1",
      "limit depth to max_depth (-1 = no limit)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profiler_memory_params[] =
{
    { "show", Parameter::PT_BOOL, nullptr, "true",
      "show module memory profile stats" },

    { "count", Parameter::PT_INT, "0:max32", "0",
      "limit results to count items per level (0 = no limit)" },

    { "sort", Parameter::PT_ENUM,
      "none | allocations | total_used | avg_allocation ",
      "total_used", "sort by given field" },

    { "max_depth", Parameter::PT_INT, "-1:255", "-1",
      "limit depth to max_depth (-1 = no limit)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profiler_rule_params[] =
{
    { "show", Parameter::PT_BOOL, nullptr, "true",
      "show rule time profile stats" },

    { "count", Parameter::PT_INT, "0:max32", "0",
      "print results to given level (0 = all)" },

    { "sort", Parameter::PT_ENUM,
      "none | checks | avg_check | total_time | matches | no_matches | "
      "avg_match | avg_no_match",
      "total_time", "sort by given field" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profiler_params[] =
{
    { "modules", Parameter::PT_TABLE, profiler_time_params, nullptr,
      "module time profiling" },

    { "memory", Parameter::PT_TABLE, profiler_memory_params, nullptr,
      "module memory profiling" },

    { "rules", Parameter::PT_TABLE, profiler_rule_params, nullptr,
      "rule time profiling" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define profiler_help \
    "configure profiling of rules and/or modules"

template<typename T>
static bool s_profiler_module_set_max_depth(T& config, Value& v)
{ config.max_depth = v.get_uint8(); return true; }

static bool s_profiler_module_set_max_depth(RuleProfilerConfig&, Value&)
{ return false; }

template<typename T>
static bool s_profiler_module_set(T& config, Value& v)
{
    if ( v.is("count") )
        config.count = v.get_uint32();

    else if ( v.is("show") )
        config.show = v.get_bool();

    else if ( v.is("sort") )
        config.sort = static_cast<typename T::Sort>(v.get_uint8());

    else if ( v.is("max_depth") )
        return s_profiler_module_set_max_depth(config, v);

    else
        return false;

    return true;
}

class ProfilerModule : public Module
{
public:
    ProfilerModule() : Module("profiler", profiler_help, profiler_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;

    Usage get_usage() const override
    { return GLOBAL; }
};

bool ProfilerModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    const char* spt = "profiler.modules";
    const char* spm = "profiler.memory";
    const char* spr = "profiler.rules";

    if ( !strncmp(fqn, spt, strlen(spt)) )
        return s_profiler_module_set(sc->profiler->time, v);

    else if ( !strncmp(fqn, spm, strlen(spm)) )
        return s_profiler_module_set(sc->profiler->memory, v);

    else if ( !strncmp(fqn, spr, strlen(spr)) )
        return s_profiler_module_set(sc->profiler->rule, v);

    return false;
}

bool ProfilerModule::end(const char*, int, SnortConfig* sc)
{
    TimeProfilerStats::set_enabled(sc->profiler->time.show);
    RuleContext::set_enabled(sc->profiler->rule.show);
    return true;
}

ProfileStats* ProfilerModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = "total";
        parent = nullptr;
        return &totalPerfStats;

    case 1:
        name = "other";
        parent = nullptr;
        return &otherPerfStats;
    }
    return nullptr;
}

//-------------------------------------------------------------------------
// classification module
//-------------------------------------------------------------------------
// FIXIT-L signature.{h,cc} has type and name confused
// the keys here make more sense

#define classifications_help \
    "define rule categories with priority"

static const Parameter classification_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "name used with classtype rule option" },

    { "priority", Parameter::PT_INT, "0:max32", "1",
      "default priority for class" },

    { "text", Parameter::PT_STRING, nullptr, nullptr,
      "description of class" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ClassificationsModule : public Module
{
public:
    ClassificationsModule() :
        Module("classifications", classifications_help, classification_params, true) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    string name;
    string text;
    unsigned priority;
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
        add_classification(sc, name.c_str(), text.c_str(), priority);
    return true;
}

bool ClassificationsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("name") )
        name = v.get_string();

    else if ( v.is("priority") )
        priority = v.get_uint32();

    else if ( v.is("text") )
        text = v.get_string();

    return true;
}

//-------------------------------------------------------------------------
// reference module
//-------------------------------------------------------------------------

#define reference_help \
    "define reference systems used in rules"

static const Parameter reference_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "name used with reference rule option" },

    { "url", Parameter::PT_STRING, nullptr, nullptr,
      "where this reference is defined" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ReferencesModule : public Module
{
public:
    ReferencesModule() :
        Module("references", reference_help, reference_params, true) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

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
        reference_system_add(sc, name, url.c_str());
    return true;
}

bool ReferencesModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("name") )
        name = v.get_string();

    else if ( v.is("url") )
        url = v.get_string();

    return true;
}

//-------------------------------------------------------------------------
// alerts module
//-------------------------------------------------------------------------
static const Parameter alerts_params[] =
{
    { "alert_with_interface_name", Parameter::PT_BOOL, nullptr, "false",
      "include interface in alert info (fast, full, or syslog only)" },

    { "detection_filter_memcap", Parameter::PT_INT, "0:max32", "1048576",
      "set available MB of memory for detection_filters" },

    { "event_filter_memcap", Parameter::PT_INT, "0:max32", "1048576",
      "set available MB of memory for event_filters" },

    { "log_references", Parameter::PT_BOOL, nullptr, "false",
      "include rule references in alert info (full only)" },

    { "order", Parameter::PT_STRING, nullptr, nullptr,
      "change the order of rule action application" },

    { "rate_filter_memcap", Parameter::PT_INT, "0:max32", "1048576",
      "set available MB of memory for rate_filters" },

    { "reference_net", Parameter::PT_STRING, nullptr, nullptr,
      "set the CIDR for homenet "
      "(for use with -l or -B, does NOT change $HOME_NET in IDS mode)" },

    { "stateful", Parameter::PT_BOOL, nullptr, "false",
      "don't alert w/o established session (note: rule action still taken)" },

    { "tunnel_verdicts", Parameter::PT_STRING, nullptr, nullptr,
      "let DAQ handle non-allow verdicts for gtp|teredo|6in4|4in6|4in4|6in6|gre|mpls|vxlan traffic" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define alerts_help \
    "configure alerts"

class AlertsModule : public Module
{
public:
    AlertsModule() : Module("alerts", alerts_help, alerts_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }
};

bool AlertsModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("alert_with_interface_name") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__ALERT_IFACE);

    else if ( v.is("detection_filter_memcap") )
        sc->detection_filter_config->memcap = v.get_uint32();

    else if ( v.is("event_filter_memcap") )
        sc->threshold_config->memcap = v.get_uint32();

    else if ( v.is("log_references") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__ALERT_REFS);

    else if ( v.is("order") )
        sc->rule_order = v.get_string();

    else if ( v.is("rate_filter_memcap") )
        sc->rate_filter_config->memcap = v.get_uint32();

    else if ( v.is("reference_net") )
        return ( sc->homenet.set(v.get_string()) == SFIP_SUCCESS );

    else if ( v.is("stateful") )
        v.update_mask(sc->run_flags, RUN_FLAG__ASSURE_EST);

    else if ( v.is("tunnel_verdicts") )
        sc->set_tunnel_verdicts(v.get_string());

    return true;
}

//-------------------------------------------------------------------------
// output module
//-------------------------------------------------------------------------

static const Parameter output_event_trace_params[] =
{
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

    { "event_trace", Parameter::PT_TABLE, output_event_trace_params, nullptr,
      "" },

    { "quiet", Parameter::PT_BOOL, nullptr, "false",
      "suppress normal logging on stdout (same as -q)" },

    { "logdir", Parameter::PT_STRING, nullptr, ".",
      "where to put log files (same as -l)" },

    { "show_year", Parameter::PT_BOOL, nullptr, "false",
      "include year in timestamp in the alert and log files (same as -y)" },

    { "tagged_packet_limit", Parameter::PT_INT, "0:max32", "256",
      "maximum number of packets tagged for non-packet metrics" },

    { "verbose", Parameter::PT_BOOL, nullptr, "false",
      "be verbose (same as -v)" },

    { "obfuscate", Parameter::PT_BOOL, nullptr, "false",
      "obfuscate the logged IP addresses (same as -O)" },

#ifdef REG_TEST
    { "wide_hex_dump", Parameter::PT_BOOL, nullptr, "true",
#else
    { "wide_hex_dump", Parameter::PT_BOOL, nullptr, "false",
#endif
      "output 20 bytes per lines instead of 16 when dumping buffers" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define output_help \
    "configure general output parameters"

static const RuleMap output_rules[] =
{
    { TAG_LOG_PKT, "tagged packet" },
    { 0, nullptr }
};

class OutputModule : public Module
{
public:
    OutputModule() : Module("output", output_help, output_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

    unsigned get_gid() const override
    { return GID_TAG; }

    const RuleMap* get_rules() const override
    { return output_rules; }
};

bool OutputModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("dump_chars_only") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__CHAR_DATA);

    else if ( v.is("dump_payload") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__APP_DATA);

    else if ( v.is("dump_payload_verbose") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__VERBOSE_DUMP);

    else if ( v.is("quiet") )
    {
        if ( v.get_bool() )
            SnortConfig::set_log_quiet(true);
    }

    else if ( v.is("logdir") )
        sc->log_dir = v.get_string();

    else if ( v.is("max_data") )
        sc->event_trace_max = v.get_uint16();

    else if ( v.is("show_year") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__INCLUDE_YEAR);

    else if ( v.is("tagged_packet_limit") )
        sc->tagged_packet_limit = v.get_uint32();

    else if ( v.is("verbose") )
    {
        if ( v.get_bool() )
            SnortConfig::enable_log_verbose();
    }
    else if ( v.is("wide_hex_dump") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__WIDE_HEX);

    else if ( v.is("obfuscate") )
        v.update_mask(sc->output_flags, OUTPUT_FLAG__OBFUSCATE);

    return true;
}

//-------------------------------------------------------------------------
// active module
//-------------------------------------------------------------------------

static const Parameter active_params[] =
{
    { "attempts", Parameter::PT_INT, "0:255", "0",
      "number of TCP packets sent per response (with varying sequence numbers)" },

    { "device", Parameter::PT_STRING, nullptr, nullptr,
      "use 'ip' for network layer responses or 'eth0' etc for link layer" },

    { "dst_mac", Parameter::PT_STRING, nullptr, nullptr,
      "use format '01:23:45:67:89:ab'" },

    { "max_responses", Parameter::PT_INT, "0:255", "0",
      "maximum number of responses" },

    { "min_interval", Parameter::PT_INT, "1:255", "255",
      "minimum number of seconds between responses" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define active_help \
    "configure responses"

static PegInfo active_pegs[]
{
    { CountType::SUM, "injects", "total crafted packets encoded and injected" },
    { CountType::SUM, "failed_injects", "total crafted packet encode + injects that failed" },
    { CountType::SUM, "direct_injects", "total crafted packets directly injected" },
    { CountType::SUM, "failed_direct_injects", "total crafted packet direct injects that failed" },
    { CountType::SUM, "holds_denied", "total number of packet hold requests denied" },
    { CountType::SUM, "holds_canceled", "total number of packet hold requests canceled" },
    { CountType::SUM, "holds_allowed", "total number of packet hold requests allowed" },
    { CountType::END, nullptr, nullptr }
};

class ActiveModule : public Module
{
public:
    ActiveModule() : Module("active", active_help, active_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return active_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*) &active_counts; }

    Usage get_usage() const override
    { return GLOBAL; }
};

bool ActiveModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("attempts") )
        sc->respond_attempts = v.get_uint8();

    else if ( v.is("device") )
        sc->respond_device = v.get_string();

    else if ( v.is("dst_mac") )
        sc->set_dst_mac(v.get_string());

    else if ( v.is("max_responses") )
        sc->max_responses = v.get_uint8();

    else if ( v.is("min_interval") )
        sc->min_interval = v.get_uint8();

    return true;
}

//-------------------------------------------------------------------------
// packets module
//-------------------------------------------------------------------------

static const Parameter packets_params[] =
{
    { "address_space_agnostic", Parameter::PT_BOOL, nullptr, "false",
      "determines whether DAQ address space info is used to track fragments and connections" },

    { "bpf_file", Parameter::PT_STRING, nullptr, nullptr,
      "file with BPF to select traffic for Snort" },

    { "limit", Parameter::PT_INT, "0:max53", "0",
      "maximum number of packets to process before stopping (0 is unlimited)" },

    { "skip", Parameter::PT_INT, "0:max53", "0",
      "number of packets to skip before before processing" },

    { "mpls_agnostic", Parameter::PT_BOOL, nullptr, "true",
      "determines whether MPLS labels are used to track fragments and connections" },

    { "vlan_agnostic", Parameter::PT_BOOL, nullptr, "false",
      "determines whether VLAN tags are used to track fragments and connections" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define packets_help \
    "configure basic packet handling"

class PacketsModule : public Module
{
public:
    PacketsModule() : Module("packets", packets_help, packets_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }
};

bool PacketsModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("address_space_agnostic") )
        sc->asid_agnostic = v.get_bool();

    else if ( v.is("bpf_file") )
        sc->bpf_file = v.get_string();

    else if ( v.is("limit") )
        sc->pkt_cnt = v.get_uint64();

    else if ( v.is("mpls_agnostic") )
        sc->mpls_agnostic = v.get_bool();

    else if ( v.is("skip") )
        sc->pkt_skip = v.get_uint64();

    else if ( v.is("vlan_agnostic") )
        sc->vlan_agnostic = v.get_bool();

    return true;
}


//-------------------------------------------------------------------------
// attribute_table module
//-------------------------------------------------------------------------

static const Parameter attribute_table_params[] =
{
    { "hosts_file", Parameter::PT_STRING, nullptr, nullptr,
      "filename to load attribute host table from" },

    { "max_hosts", Parameter::PT_INT, "32:max53", "1024",
      "maximum number of hosts in attribute table" },

    { "max_services_per_host", Parameter::PT_INT, "1:65535", "8",
      "maximum number of services per host entry in attribute table" },

    { "max_metadata_services", Parameter::PT_INT, "1:255", "9",
      "maximum number of services in rule" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const char* attribute_table_help =
    "configure hosts loading";

class AttributeTableModule : public Module
{
public:
    AttributeTableModule() :
        Module("attribute_table", attribute_table_help, attribute_table_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }
};

bool AttributeTableModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("hosts_file") )
        sc->attribute_hosts_file = std::string(v.get_string());

    else if ( v.is("max_hosts") )
        sc->max_attribute_hosts = v.get_uint32();

    else if ( v.is("max_services_per_host") )
        sc->max_attribute_services_per_host = v.get_uint16();

    else if ( v.is("max_metadata_services") )
        sc->max_metadata_services = v.get_uint8();

    return true;
}

//-------------------------------------------------------------------------
// network module
//-------------------------------------------------------------------------

static const Parameter network_params[] =
{
    { "checksum_drop", Parameter::PT_MULTI,
      "all | ip | noip | tcp | notcp | udp | noudp | icmp | noicmp | none", "none",
      "drop if checksum is bad" },

    { "checksum_eval", Parameter::PT_MULTI,
      "all | ip | noip | tcp | notcp | udp | noudp | icmp | noicmp | none", "all",
      "checksums to verify" },

    { "id", Parameter::PT_INT, "0:65535", "0",
      "correlate unified2 events with configuration" },

    { "min_ttl", Parameter::PT_INT, "1:255", "1",
      "alert / normalize packets with lower TTL / hop limit "
      "(you must enable rules and / or normalization also)" },

    { "new_ttl", Parameter::PT_INT, "1:255", "1",
      "use this value for responses and when normalizing" },

    { "layers", Parameter::PT_INT, "3:255", "40",
      "the maximum number of protocols that Snort can correctly decode" },

    { "max_ip6_extensions", Parameter::PT_INT, "0:255", "0",
      "the maximum number of IP6 options Snort will process for a given IPv6 layer "
      "before raising 116:456 (0 = unlimited)" },

    { "max_ip_layers", Parameter::PT_INT, "0:255", "0",
      "the maximum number of IP layers Snort will process for a given packet "
      "before raising 116:293 (0 = unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define network_help \
    "configure basic network parameters"

class NetworkModule : public Module
{
public:
    NetworkModule() : Module("network", network_help, network_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }
};

bool NetworkModule::set(const char*, Value& v, SnortConfig* sc)
{
    NetworkPolicy* p = get_network_policy();

    if ( v.is("checksum_drop") )
        ConfigChecksumDrop(v.get_string());

    else if ( v.is("checksum_eval") )
        ConfigChecksumMode(v.get_string());

    else if ( v.is("id") )
        p->user_policy_id = v.get_uint16();

    else if ( v.is("min_ttl") )
        p->min_ttl = v.get_uint8();

    else if ( v.is("new_ttl") )
        p->new_ttl = v.get_uint8();

    else if (v.is("layers"))
        sc->num_layers = v.get_uint8();

    else if (v.is("max_ip6_extensions"))
        sc->max_ip6_extensions = v.get_uint8();

    else if (v.is("max_ip_layers"))
        sc->max_ip_layers = v.get_uint8();

    return true;
}

bool NetworkModule::end(const char*, int idx, SnortConfig* sc)
{
    if (!idx)
    {
        NetworkPolicy* p = get_network_policy();
        sc->policy_map->set_user_network(p);
    }
    return true;
}

//-------------------------------------------------------------------------
// inspection policy module
//-------------------------------------------------------------------------

static const Parameter inspection_params[] =
{
    { "id", Parameter::PT_INT, "0:65535", "0",
      "correlate policy and events with other items in configuration" },

#ifdef HAVE_UUID
    { "uuid", Parameter::PT_STRING, nullptr, nullptr,
      "correlate events by uuid" },
#endif

    { "mode", Parameter::PT_ENUM, "inline | inline-test", "inline-test",
      "set policy mode" },

    { "max_aux_ip", Parameter::PT_INT, "-1:127", "16",
      "maximum number of auxiliary IPs per flow to detect and save "
      "(-1 = disable, 0 = detect but don't save, 1+ = save in FIFO manner)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define inspection_help \
    "configure basic inspection policy parameters"

class InspectionModule : public Module
{
public:
    InspectionModule() : Module("inspection", inspection_help, inspection_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }
};

bool InspectionModule::set(const char*, Value& v, SnortConfig* sc)
{
    InspectionPolicy* p = get_inspection_policy();

    if ( v.is("id") )
        p->user_policy_id = v.get_uint16();

#ifdef HAVE_UUID
    else if ( v.is("uuid") )
    {
        if(uuid_parse(v.get_string(), p->uuid) != 0)
        {
            ParseError("Invalid Inspection UUID: %s", v.get_string());
            uuid_clear(p->uuid);
        }
    }
#endif

    else if ( v.is("mode") )
    {
        switch ( v.get_uint8() )
        {
            case 0:
                p->policy_mode = POLICY_MODE__INLINE;
                break;
            case 1:
                p->policy_mode = POLICY_MODE__INLINE_TEST;
                break;
            default:
                break;
        }
    }

    else if ( v.is("max_aux_ip") )
        sc->max_aux_ip = v.get_int16();

    return true;
}

bool InspectionModule::end(const char*, int, SnortConfig* sc)
{
    InspectionPolicy* p = get_inspection_policy();
    sc->policy_map->set_user_inspection(p);
    return true;
}

//-------------------------------------------------------------------------
// Ips policy module
//-------------------------------------------------------------------------

static const char* get_var_name(const char* fqn)
{
    const char* ptr = strrchr(fqn, '.');
    assert(ptr);
    return ptr + 1;
}

static const Parameter var_params[] =
{
    { "$var" , Parameter::PT_STRING, nullptr, nullptr,
      "IPS policy variable" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter variable_params[] =
{
    { "nets" , Parameter::PT_TABLE, var_params, nullptr,
      "net variables" },

    { "paths" , Parameter::PT_TABLE, var_params, nullptr,
      "path variables" },

    { "ports" , Parameter::PT_TABLE, var_params, nullptr,
      "port variables" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter action_map_params[] =
{
    { "replace" , Parameter::PT_STRING, nullptr, nullptr,
      "action you want to change" },

    { "with" , Parameter::PT_STRING, nullptr, nullptr,
      "action you want to use instead" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ips_params[] =
{
    { "action_map", Parameter::PT_LIST, action_map_params, nullptr,
      "change actions like block to alert (applied after action_override)" },

    { "action_override", Parameter::PT_STRING, nullptr, nullptr,
      "use this action for all rules (applied before action_map)" },

    { "default_rule_state", Parameter::PT_ENUM, "no | yes | inherit", "inherit",
      "enable or disable ips rules" },

    { "enable_builtin_rules", Parameter::PT_BOOL, nullptr, "false",
      "enable events from builtin rules w/o stubs" },

    { "id", Parameter::PT_INT, "0:65535", "0",
      "correlate unified2 events with configuration" },

    { "include", Parameter::PT_STRING, nullptr, nullptr,
      "snort rules and includes" },

    { "includer", Parameter::PT_STRING, "(optional)", nullptr,
      "for internal use; where includes are included from" },

    // FIXIT-L no default; it breaks initialization by -Q
    { "mode", Parameter::PT_ENUM, "tap | inline | inline-test", nullptr,
      "set policy mode" },

    { "obfuscate_pii", Parameter::PT_BOOL, nullptr, "false",
      "mask all but the last 4 characters of credit card and social security numbers" },

    { "rules", Parameter::PT_STRING, nullptr, nullptr,
      "snort rules and includes (may contain states too)" },

    { "states", Parameter::PT_STRING, nullptr, nullptr,
      "snort rule states and includes (may contain rules too)" },

#ifdef HAVE_UUID
    { "uuid", Parameter::PT_STRING, nullptr, "00000000-0000-0000-0000-000000000000",
      "IPS policy uuid" },
#endif

    { "variables", Parameter::PT_TABLE, variable_params, nullptr,
      "defines IPS policy variables" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define ips_help \
    "configure IPS rule processing"

class IpsModule : public Module
{
public:
    IpsModule() : Module("ips", ips_help, ips_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool matches(const char*, std::string&) override;

    Usage get_usage() const override
    { return DETECT; }

private:
    std::string replace;
    std::string with;
};

bool IpsModule::matches(const char*, std::string&)
{ return true; }

bool IpsModule::set(const char* fqn, Value& v, SnortConfig*)
{
    IpsPolicy* p = get_ips_policy();

    if ( v.is("action_override") )
        p->action_override = v.get_string();

    else if ( v.is("default_rule_state") )
        p->default_rule_state = (IpsPolicy::Enable)v.get_uint8();

    else if ( v.is("enable_builtin_rules") )
        p->enable_builtin_rules = v.get_bool();

    else if ( v.is("id") )
        p->user_policy_id = v.get_uint16();

    else if ( v.is("include") )
        p->include = v.get_string();

    else if ( v.is("includer") )
        p->includer = v.get_string();

    else if ( v.is("mode") )
        p->policy_mode = (PolicyMode)v.get_uint8();

    else if ( v.is("obfuscate_pii") )
        p->obfuscate_pii = v.get_bool();

    else if ( v.is("replace") )
        replace = v.get_string();

    else if ( v.is("rules") )
        p->rules += v.get_string();

    else if ( v.is("states") )
        p->states += v.get_string();

#ifdef HAVE_UUID
    else if ( v.is("uuid") )
    {
        if(uuid_parse(v.get_string(), p->uuid) != 0)
        {
            ParseError("Invalid IPS UUID: %s", v.get_string());
            uuid_clear(p->uuid);
        }
    }
#endif

    // FIXIT-M should only need one table with dynamically typed vars
    else if ( strstr(fqn, "variables.nets.") )
        ParseIpVar(get_var_name(fqn), v.get_string());

    else if ( strstr(fqn, "variables.paths.") )
        ParsePathVar(get_var_name(fqn), v.get_string());

    else if ( strstr(fqn, "variables.ports.") )
        ParsePortVar(get_var_name(fqn), v.get_string());

    else if ( v.is("with") )
        with = v.get_string();

    return true;
}

bool IpsModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( idx and !strcmp(fqn, "ips.action_map") )
    {
        if ( replace.empty() or with.empty() )
        {
            ParseError("%s - must set both replace and with", fqn);
            return false;
        }

        IpsPolicy* p = get_ips_policy();
        p->action_map[replace] = with;

        replace.clear();
        with.clear();
    }
    else if (!idx and !strcmp(fqn, "ips"))
    {
        IpsPolicy* p = get_ips_policy();
        sc->policy_map->set_user_ips(p);
    }
    return true;
}

//-------------------------------------------------------------------------
// process module
//-------------------------------------------------------------------------

static const Parameter thread_pinning_params[] =
{
    { "cpuset", Parameter::PT_STRING, nullptr, nullptr,
      "pin the associated thread to this cpuset" },

    { "thread", Parameter::PT_INT, "0:65535", nullptr,
      "set cpu affinity for the <cur_thread_num> thread that runs" },

    { "type", Parameter::PT_ENUM, "other|packet|main", nullptr,
      "define which threads will have specified affinity, by their type" },

    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "define which threads will have specified affinity, by thread name" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter process_params[] =
{
    { "chroot", Parameter::PT_STRING, nullptr, nullptr,
      "set chroot directory (same as -t)" },

    { "threads", Parameter::PT_LIST, thread_pinning_params, nullptr,
      "thread pinning parameters" },

    { "daemon", Parameter::PT_BOOL, nullptr, "false",
      "fork as a daemon (same as -D)" },

    { "dirty_pig", Parameter::PT_BOOL, nullptr, "false",
      "shutdown without internal cleanup" },

    { "set_gid", Parameter::PT_STRING, nullptr, nullptr,
      "set group ID (same as -g)" },

    { "set_uid", Parameter::PT_STRING, nullptr, nullptr,
      "set user ID (same as -u)" },

    { "umask", Parameter::PT_INT, "0x000:0x1FF", nullptr,
      "set process umask (same as -m)" },

    { "utc", Parameter::PT_BOOL, nullptr, "false",
      "use UTC instead of local time for timestamps" },

    { "watchdog_timer", Parameter::PT_INT, "0:60", "0",
      "watchdog timer for packet threads (seconds, 0 to disable)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define process_help \
    "configure basic process setup"

class ProcessModule : public Module
{
public:
    ProcessModule() : Module("process", process_help, process_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    int thread;
    CpuSet* cpuset;
    string type;
    string name;
};

bool ProcessModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("daemon") )
    {
        if ( v.get_bool() )  // FIXIT-M fix cmd line vs conf conflicts
            sc->set_daemon(true);
    }
    else if ( v.is("chroot") )
        sc->set_chroot_dir(v.get_string());

    else if ( v.is("dirty_pig") )
        sc->set_dirty_pig(v.get_bool());

    else if ( v.is("set_gid") )
        sc->set_gid(v.get_string());

    else if ( v.is("set_uid") )
        sc->set_uid(v.get_string());

    else if ( v.is("umask") )
        sc->set_umask(v.get_uint32());

    else if ( v.is("utc") )
        sc->set_utc(v.get_bool());

    else if (v.is("cpuset"))
    {
        if (!(cpuset = ThreadConfig::validate_cpuset_string(v.get_string())))
            return false;
    }

    else if (v.is("thread"))
        thread = v.get_uint16();

    else if (v.is("type"))
        type = v.get_string();

    else if (v.is("name"))
        name = v.get_string();

    else if ( v.is("watchdog_timer") )
        sc->set_watchdog(v.get_uint16());

    return true;
}

bool ProcessModule::begin(const char*, int, SnortConfig*)
{
    thread = -1;
    cpuset = nullptr;
    type.clear();
    name.clear();
    return true;
}

bool ProcessModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( !idx )
        return true;

    if (!strcmp(fqn, "process.threads"))
    {
        if (!cpuset)
        {
            ParseError("%s - no cpuset specified", fqn);
            return false;
        }

        if (thread >= 0)
        {
            // Packet thread affinity.
            if ( !(name.empty() && (type.empty() || type == "packet")) )
            {
                ParseError("%s - type or name specified for thread %d", fqn, thread);
                ThreadConfig::destroy_cpuset(cpuset);
                return false;
            }

            // Thread type is implicitly "packet".
            sc->thread_config->set_thread_affinity(STHREAD_TYPE_PACKET, thread, cpuset);
        }

        else if (!type.empty() && name.empty())
        {
            // Type-based affinity: main, or other.
            thread = ThreadConfig::DEFAULT_THREAD_ID;
            if (type == "main")
                sc->thread_config->set_thread_affinity(STHREAD_TYPE_MAIN, thread, cpuset);
            else if (type == "other")
                sc->thread_config->set_thread_affinity(STHREAD_TYPE_OTHER, thread, cpuset);
            else
            {
                ParseError("%s - bad thread type %s", fqn, type.c_str());
                ThreadConfig::destroy_cpuset(cpuset);
                return false;
            }
        }

        else if (type.empty() && !name.empty())
        {
            // name-based affinity
            sc->thread_config->set_named_thread_affinity(name, cpuset);
        }

        else if (!type.empty() && !name.empty())
        {
            ParseError("%s - can't specify both type and name", fqn);
            ThreadConfig::destroy_cpuset(cpuset);
            return false;
        }

        else
        {
            ParseError("%s - none of thread, type or name specified", fqn);
            ThreadConfig::destroy_cpuset(cpuset);
            return false;
        }
    }

    return true;
}

//-------------------------------------------------------------------------
// suppress module
//-------------------------------------------------------------------------

static const Parameter suppress_params[] =
{
    { "gid", Parameter::PT_INT, "0:max32", "0",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "0:max32", "0",
      "rule signature ID" },

    { "track", Parameter::PT_ENUM, "by_src | by_dst", nullptr,
      "suppress only matching source or destination addresses" },

    { "ip", Parameter::PT_STRING, nullptr, nullptr,
      "restrict suppression to these addresses according to track" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define suppress_help \
    "configure event suppressions"

class SuppressModule : public Module
{
public:
    SuppressModule() : Module("suppress", suppress_help, suppress_params, true) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

private:
    THDX_STRUCT thdx;
};

bool SuppressModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("gid") )
        thdx.gen_id = v.get_uint32();

    else if ( v.is("sid") )
        thdx.sig_id = v.get_uint32();

    else if ( v.is("track") )
        thdx.tracking = v.get_uint8() + 1;

    else if ( v.is("ip") )
        thdx.ip_address = sfip_var_from_string(v.get_string(), "suppress");

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
    if ( idx && sfthreshold_create(sc, sc->threshold_config, &thdx, get_network_policy()->policy_id) )
    {
        ParseError("bad suppress configuration [%d]", idx);
        return false;
    }
    return true;
}

//-------------------------------------------------------------------------
// event_filter module
//-------------------------------------------------------------------------

static const Parameter event_filter_params[] =
{
    { "gid", Parameter::PT_INT, "0:max32", "1",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "0:max32", "1",
      "rule signature ID" },

    { "type", Parameter::PT_ENUM, "limit | threshold | both", nullptr,
      "1st count events | every count events | once after count events" },

    { "track", Parameter::PT_ENUM, "by_src | by_dst", nullptr,
      "filter only matching source or destination addresses" },

    { "count", Parameter::PT_INT, "-1:max31", "0",
      "number of events in interval before tripping; -1 to disable" },

    { "seconds", Parameter::PT_INT, "0:max32", "0",
      "count interval" },

    { "ip", Parameter::PT_STRING, nullptr, nullptr,
      "restrict filter to these addresses according to track" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define event_filter_help \
    "configure thresholding of events"

extern THREAD_LOCAL EventFilterStats event_filter_stats; // in sfthd.cc
const PegInfo event_filter_peg_names[] =
{
    { CountType::SUM, "no_memory_local", "number of times event filter ran out of local memory" },
    { CountType::SUM, "no_memory_global", "number of times event filter ran out of global memory" },
    { CountType::END, nullptr, nullptr }
};

class EventFilterModule : public Module
{
public:
    EventFilterModule() :
        Module("event_filter", event_filter_help, event_filter_params, true) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    {
        return event_filter_peg_names;
    }

    PegCount* get_counts() const override
    {
        return (PegCount*)&event_filter_stats;
    }

    Usage get_usage() const override
    { return CONTEXT; }

private:
    THDX_STRUCT thdx;
};

bool EventFilterModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("gid") )
        thdx.gen_id = v.get_uint32();

    else if ( v.is("sid") )
        thdx.sig_id = v.get_uint32();

    else if ( v.is("track") )
        thdx.tracking = v.get_uint8() + 1;

    else if ( v.is("ip") )
        thdx.ip_address = sfip_var_from_string(v.get_string(), "event_filter");

    else if ( v.is("count") )
        thdx.count = v.get_int32();

    else if ( v.is("seconds") )
        thdx.seconds = v.get_uint32();

    else if ( v.is("type") )
        thdx.type = v.get_uint8();

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
    if ( idx && sfthreshold_create(sc, sc->threshold_config, &thdx, get_network_policy()->policy_id) )
    {
        ParseError("bad event_filter configuration [%d]", idx);
        return false;
    }
    return true;
}

//-------------------------------------------------------------------------
// rate_filter module
//-------------------------------------------------------------------------

function<const char*()> get_action_types = []()
{ return PluginManager::get_available_plugins(PT_IPS_ACTION); };

static const Parameter rate_filter_params[] =
{
    { "gid", Parameter::PT_INT, "0:max32", "1",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "0:max32", "1",
      "rule signature ID" },

    { "track", Parameter::PT_ENUM, "by_src | by_dst | by_rule", "by_src",
      "filter only matching source or destination addresses" },

    { "count", Parameter::PT_INT, "0:max32", "1",
      "number of events in interval before tripping" },

    { "seconds", Parameter::PT_INT, "0:max32", "1",
      "count interval" },

    { "new_action", Parameter::PT_DYNAMIC, (void*)&get_action_types, "alert",
      "take this action on future hits until timeout" },

    { "timeout", Parameter::PT_INT, "0:max32", "1",
      "count interval" },

    { "apply_to", Parameter::PT_STRING, nullptr, nullptr,
      "restrict filter to these addresses according to track" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define rate_filter_help \
    "configure rate filters (which change rule actions)"

extern THREAD_LOCAL RateFilterStats rate_filter_stats;
const PegInfo rate_filter_peg_names[] =
{
    { CountType::SUM, "no_memory", "number of times rate filter ran out of memory" },
    { CountType::END, nullptr, nullptr }
};


class RateFilterModule : public Module
{
public:
    RateFilterModule() : Module("rate_filter", rate_filter_help, rate_filter_params, true)
    { thdx.applyTo = nullptr; }
    ~RateFilterModule() override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    {
        return rate_filter_peg_names;
    }

    PegCount* get_counts() const override
    {
        return (PegCount*)&rate_filter_stats;
    }

    Usage get_usage() const override
    { return CONTEXT; }

private:
    tSFRFConfigNode thdx;
};

RateFilterModule::~RateFilterModule()
{
    if ( thdx.applyTo )
        sfvar_free(thdx.applyTo);
}

bool RateFilterModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("gid") )
        thdx.gid = v.get_uint32();

    else if ( v.is("sid") )
        thdx.sid = v.get_uint32();

    else if ( v.is("track") )
        thdx.tracking = (SFRF_TRACK)(v.get_uint8() + 1);

    else if ( v.is("count") )
        thdx.count = v.get_uint32();

    else if ( v.is("seconds") )
        thdx.seconds = v.get_uint32();

    else if ( v.is("timeout") )
        thdx.timeout = v.get_uint32();

    else if ( v.is("apply_to") )
        thdx.applyTo = sfip_var_from_string(v.get_string(), "rate_filter");

    else if ( v.is("new_action") )
    {
        thdx.newAction = Actions::get_type(v.get_string());

        if ( !Actions::is_valid_action(thdx.newAction) )
            ParseError("unknown new_action type rate_filter configuration %s",
                    v.get_string());
    }

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
        ParseError("bad rate_filter configuration [%d]", idx);

    thdx.applyTo = nullptr;
    return true;
}

//-------------------------------------------------------------------------
// hosts module
//-------------------------------------------------------------------------

static const Parameter service_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "service identifier" },

    { "proto", Parameter::PT_ENUM, "tcp | udp", "tcp",
      "IP protocol" },

    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port number" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter hosts_params[] =
{
    { "ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32",
      "hosts address / CIDR" },

    { "frag_policy", Parameter::PT_ENUM, IP_POLICIES, nullptr,
      "defragmentation policy" },

    { "tcp_policy", Parameter::PT_ENUM, TCP_POLICIES, nullptr,
      "TCP reassembly policy" },

    { "services", Parameter::PT_LIST, service_params, nullptr,
      "list of service parameters" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define hosts_help \
    "configure hosts"

class HostsModule : public Module
{
public:
    HostsModule() : Module("hosts", hosts_help, hosts_params, true)
    { host = nullptr; }

    ~HostsModule() override
    { assert(!host); }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return HostAttributesManager::get_pegs(); }

    PegCount* get_counts() const override
    { return HostAttributesManager::get_peg_counts(); }

    Usage get_usage() const override
    { return GLOBAL; }

private:
    HostServiceDescriptor service;
    HostAttributesEntry host;
};

bool HostsModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( host and v.is("ip") )
    {
        SfIp addr;
        v.get_addr(addr);
        host->set_ip_addr(addr);
    }

    else if ( host and v.is("frag_policy") )
        host->set_frag_policy(v.get_uint8() + 1);

    else if ( host and v.is("tcp_policy") )
        host->set_stream_policy(v.get_uint8());

    else if ( v.is("name") )
        service.snort_protocol_id = sc->proto_ref->add(v.get_string());

    else if ( v.is("proto") )
        service.ipproto = sc->proto_ref->add(v.get_string());

    else if ( v.is("port") )
        service.port = v.get_uint16();

    return true;
}

bool HostsModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "hosts.services") )
        service.reset();
    else if ( idx && !strcmp(fqn, "hosts") )
        host.reset(new HostAttributesDescriptor);

    return true;
}

bool HostsModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( idx && !strcmp(fqn, "hosts.services") )
    {
        bool updated = false;
        host->update_service(service.port, service.ipproto, service.snort_protocol_id, updated);
        service.reset();
    }
    else if ( idx && !strcmp(fqn, "hosts") )
    {
        if ( !HostAttributesManager::add_host(host, sc) )
            host.reset();
        host = nullptr;
    }

    return true;
}

//-------------------------------------------------------------------------
// File policy module
//-------------------------------------------------------------------------

static const Parameter file_when_params[] =
{
    // FIXIT-M when.policy_id should be an arbitrary string auto converted
    // into index for binder matching and lookups
    { "file_type_id", Parameter::PT_INT, "0:max32", "0",
      "unique ID for file type in file magic rule" },

    { "sha256", Parameter::PT_STRING, nullptr, nullptr,
      "SHA 256" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_use_params[] =
{
    { "verdict", Parameter::PT_ENUM, "unknown | log | stop | block | reset ", "unknown",
      "what to do with matching traffic" },

    { "enable_file_type", Parameter::PT_BOOL, nullptr, "false",
      "true/false -> enable/disable file type identification" },

    { "enable_file_signature", Parameter::PT_BOOL, nullptr, "false",
      "true/false -> enable/disable file signature" },

    { "enable_file_capture", Parameter::PT_BOOL, nullptr, "false",
      "true/false -> enable/disable file capture" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_policy_rule_params[] =
{
    { "when", Parameter::PT_TABLE, file_when_params, nullptr,
      "match criteria" },

    { "use", Parameter::PT_TABLE, file_use_params, nullptr,
      "target configuration" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_policy_params[] =
{
    { "enable_type", Parameter::PT_BOOL, nullptr, "true",
      "enable type ID" },

    { "enable_signature", Parameter::PT_BOOL, nullptr, "false",
      "enable signature calculation" },

    { "enable_capture", Parameter::PT_BOOL, nullptr, "false",
      "enable file capture" },

    { "verdict_delay", Parameter::PT_INT, "0:max53", "0",
      "number of queries to return final verdict" },

    { "rules", Parameter::PT_LIST, file_policy_rule_params, nullptr,
      "list of file rules" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


#define file_policy_help "configure file policy"

class FilePolicyModule : public Module
{
public:
    FilePolicyModule() : Module("file_policy", file_policy_help, file_policy_params)
    { }
    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

private:
    FileRule file_rule;
};

bool FilePolicyModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if (idx && !strcmp(fqn, "file_policy.rules"))
        file_rule.clear();
    return true;
}

bool FilePolicyModule::set(const char*, Value& v, SnortConfig*)
{
    FilePolicy* fp = get_network_policy()->get_file_policy();
    if ( v.is("file_type_id") )
        file_rule.when.type_id = v.get_uint32();

    else if ( v.is("sha256") )
        file_rule.when.sha256 = v.get_string();

    else if ( v.is("verdict") )
        file_rule.use.verdict = (FileVerdict)v.get_uint8();

    else if ( v.is("enable_file_type") )
        file_rule.use.type_enabled = v.get_bool();

    else if ( v.is("enable_file_signature") )
        file_rule.use.signature_enabled = v.get_bool();

    else if ( v.is("enable_file_capture") )
    {
        file_rule.use.capture_enabled = v.get_bool();
        if (file_rule.use.capture_enabled && Snort::is_reloading()
            && !FileService::is_file_capture_enabled())
        {
            ReloadError("Changing file_id.enable_file_capture requires a restart.\n");
            return false;
        }
    }

    else if ( v.is("enable_type") )
        fp->set_file_type(v.get_bool());

    else if ( v.is("enable_signature") )
        fp->set_file_signature(v.get_bool());

    else if ( v.is("enable_capture") )
    {
        if (v.get_bool() and Snort::is_reloading() and !FileService::is_file_capture_enabled())
        {
            ReloadError("Changing file_id.enable_capture requires a restart.\n");
            return false;
        }
        fp->set_file_capture(v.get_bool());
    }

    else if ( v.is("verdict_delay") )
        fp->set_verdict_delay(v.get_int64());

    return true;
}

bool FilePolicyModule::end(const char* fqn, int idx, SnortConfig*)
{
    if (!idx)
        get_network_policy()->get_file_policy()->load();
    if (idx && !strcmp(fqn, "file_policy.rules"))
        get_network_policy()->add_file_policy_rule(file_rule);

    return true;
}

//-------------------------------------------------------------------------
// module manager stuff - move to framework/module_manager.cc
//-------------------------------------------------------------------------

void module_init()
{
    // parameters must be settable regardless of sequence
    // since Lua calls this by table hash key traversal
    // (which is effectively random)
    // so module interdependencies must come after this phase
    ModuleManager::add_module(get_snort_module());

    // these modules are not policy specific
    ModuleManager::add_module(new ClassificationsModule);
    ModuleManager::add_module(new CodecModule);
    ModuleManager::add_module(new DetectionModule);
    ModuleManager::add_module(new MemoryModule);
    ModuleManager::add_module(new PacketTracerModule);
    ModuleManager::add_module(new PacketsModule);
    ModuleManager::add_module(new ProcessModule);
    ModuleManager::add_module(new ProfilerModule);
    ModuleManager::add_module(new ReferencesModule);
    ModuleManager::add_module(new SearchEngineModule);
    ModuleManager::add_module(new SFDAQModule);
    ModuleManager::add_module(new PayloadInjectorModule);

    // these could but probably shouldn't be policy specific
    // or should be broken into policy and non-policy parts
    ModuleManager::add_module(new AlertsModule);
    ModuleManager::add_module(new EventQueueModule);
    ModuleManager::add_module(new OutputModule);

    // these modules could be in traffic policy
    ModuleManager::add_module(new ActiveModule);

    ModuleManager::add_module(new LatencyModule);

    ModuleManager::add_module(new SideChannelModule);
    ModuleManager::add_module(new HighAvailabilityModule);

    // these modules should be in ips policy
    ModuleManager::add_module(new EventFilterModule);
    ModuleManager::add_module(new RateFilterModule);
    ModuleManager::add_module(new SuppressModule);

    // these are preliminary policies
    ModuleManager::add_module(new NetworkModule);
    ModuleManager::add_module(new InspectionModule);
    ModuleManager::add_module(new IpsModule);
    ModuleManager::add_module(new FilePolicyModule);

    // these modules replace config and hosts.xml
    ModuleManager::add_module(new AttributeTableModule);
    ModuleManager::add_module(new HostsModule);
    ModuleManager::add_module(new HostTrackerModule);
    ModuleManager::add_module(new HostCacheModule);
    // The TraceModule must be added last so that it can properly generate its Parameter table
    ModuleManager::add_module(new TraceModule);
}
