//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// detection_module.cc author Oleksandr Serhiienko <oserhiie@cisco.com>
// based on work by Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection_module.h"

#include <sys/resource.h>

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "trace/trace.h"

#include "detect_trace.h"

using namespace snort;

THREAD_LOCAL const Trace* detection_trace = nullptr;

#ifdef DEBUG_MSGS
static const TraceOption detection_trace_options[] =
{
    { "detect_engine", TRACE_DETECTION_ENGINE,  "enable detection engine trace logging" },
    { "rule_eval",     TRACE_RULE_EVAL,         "enable rule evaluation trace logging" },
    { "buffer",        TRACE_BUFFER,            "enable buffer trace logging" },
    { "rule_vars",     TRACE_RULE_VARS,         "enable rule variables trace logging" },
    { "fp_search",     TRACE_FP_SEARCH,         "enable fast pattern search trace logging" },
    { "pkt_detect",    TRACE_PKT_DETECTION,     "enable packet detection trace logging" },
    { "opt_tree",      TRACE_OPTION_TREE,       "enable tree option trace logging" },
    { "tag",           TRACE_TAG,               "enable tag trace logging" },
    { nullptr, 0, nullptr }
};
#endif

static const Parameter detection_params[] =
{
    { "allow_missing_so_rules", Parameter::PT_BOOL, nullptr, "false",
      "warn (true) or error (false) when an SO rule stub refers to an SO rule that isn't loaded" },

    { "asn1", Parameter::PT_INT, "0:65535", "0",
      "maximum decode nodes" },

    { "global_default_rule_state", Parameter::PT_BOOL, nullptr, "true",
      "enable or disable rules by default (overridden by ips policy settings)" },

    { "global_rule_state", Parameter::PT_BOOL, nullptr, "false",
      "apply rule_state against all policies" },

#ifdef HAVE_HYPERSCAN
    { "hyperscan_literals", Parameter::PT_BOOL, nullptr, "false",
      "use hyperscan for content literal searches instead of boyer-moore" },
#endif

    { "offload_limit", Parameter::PT_INT, "0:max32", "99999",
      "minimum sizeof PDU to offload fast pattern search (defaults to disabled)" },

    { "offload_threads", Parameter::PT_INT, "0:max32", "0",
      "maximum number of simultaneous offloads (defaults to disabled)" },

    { "pcre_enable", Parameter::PT_BOOL, nullptr, "true",
      "enable pcre pattern matching" },

    { "pcre_match_limit", Parameter::PT_INT, "0:max32", "1500",
      "limit pcre backtracking, 0 = off" },

    { "pcre_match_limit_recursion", Parameter::PT_INT, "0:max32", "1500",
      "limit pcre stack consumption, 0 = off" },

    { "pcre_override", Parameter::PT_BOOL, nullptr, "true",
      "enable pcre match limit overrides when pattern matching (ie ignore /O)" },

#ifdef HAVE_HYPERSCAN
    { "pcre_to_regex", Parameter::PT_BOOL, nullptr, "false",
      "enable the use of regex instead of pcre for compatible expressions" },
#endif

    { "enable_address_anomaly_checks", Parameter::PT_BOOL, nullptr, "false",
      "enable check and alerting of address anomalies" },

    { "enable_strict_reduction", Parameter::PT_BOOL, nullptr, "false",
      "enable strict deduplication of rule headers by ports (saves memory, but "
      "loses some speed during config reading)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};
/* *INDENT-ON* */

#define detection_help \
    "configure general IPS rule processing parameters"

#define s_name "detection"

DetectionModule::DetectionModule() : Module(s_name, detection_help, detection_params)
{ }

void DetectionModule::set_trace(const Trace* trace) const
{ detection_trace = trace; }

const TraceOption* DetectionModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    return detection_trace_options;
#endif
}

bool DetectionModule::end(const char*, int, SnortConfig* sc)
{
    if ( sc->offload_threads and ThreadConfig::get_instance_max() != 1 )
        ParseError("You can not enable experimental offload with more than one packet thread.");

    return true;
}

bool DetectionModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("allow_missing_so_rules") )
        sc->allow_missing_so_rules = v.get_bool();

    else if ( v.is("asn1") )
        sc->asn1_mem = v.get_uint16();

    else if ( v.is("global_default_rule_state") )
        sc->global_default_rule_state = v.get_bool();

    else if ( v.is("global_rule_state") )
        sc->global_rule_state = v.get_bool();

#ifdef HAVE_HYPERSCAN
    else if ( v.is("hyperscan_literals") )
        sc->hyperscan_literals = v.get_bool();
#endif

    else if ( v.is("offload_limit") )
        sc->offload_limit = v.get_uint32();

    else if ( v.is("offload_threads") )
        sc->offload_threads = v.get_uint32();

    else if ( v.is("pcre_enable") )
        v.update_mask(sc->run_flags, RUN_FLAG__NO_PCRE, true);

    else if ( v.is("pcre_match_limit") )
        sc->pcre_match_limit = v.get_uint32();

    else if ( v.is("pcre_match_limit_recursion") )
    {
        // Cap the pcre recursion limit to not exceed the stack size.
        //
        // Note that even if we tried to call setrlimit() here, the threads
        // will still get the stack size decided upon the start of snort3,
        // which is 2M (for x86_64!) if snort3 started with unlimited
        // stack size (ulimit -s). See the pthread_create() man page, or glibc
        // source code.

        // Determine the current stack size limit:
        rlimit lim;
        getrlimit(RLIMIT_STACK, &lim);
        rlim_t thread_stack_size = lim.rlim_cur;

        const size_t fudge_factor = 1 << 19;         // 1/2 M
        const size_t pcre_stack_frame_size = 1024;   // pcretest -m -C

        if (lim.rlim_cur == RLIM_INFINITY)
            thread_stack_size = 1 << 21;             // 2M

        long int max_rec = (thread_stack_size - fudge_factor) / pcre_stack_frame_size;
        if (max_rec < 0)
            max_rec = 0;

        sc->pcre_match_limit_recursion = v.get_uint32();
        if (sc->pcre_match_limit_recursion > max_rec)
        {
            sc->pcre_match_limit_recursion = max_rec;
            LogMessage("Capping pcre_match_limit_recursion to %ld, thread stack_size %ld.\n",
                sc->pcre_match_limit_recursion, thread_stack_size);
        }
    }

    else if ( v.is("pcre_override") )
        sc->pcre_override = v.get_bool();

#ifdef HAVE_HYPERSCAN
    else if ( v.is("pcre_to_regex") )
        sc->pcre_to_regex = v.get_bool();
#endif

    else if ( v.is("enable_address_anomaly_checks") )
        sc->address_anomaly_check_enabled = v.get_bool();

    else if ( v.is("enable_strict_reduction") )
        sc->enable_strict_reduction = v.get_bool();

    return true;
}
