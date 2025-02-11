//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// snort_ml_module.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_ml_module.h"

#include "log/messages.h"
#include "service_inspectors/http_inspect/http_field.h"

using namespace snort;

THREAD_LOCAL const Trace* snort_ml_trace = nullptr;

static const Parameter snort_ml_params[] =
{
    { "uri_depth", Parameter::PT_INT, "-1:max31", "-1",
      "number of input HTTP URI bytes to scan (-1 unlimited)" },

    { "client_body_depth", Parameter::PT_INT, "-1:max31", "0",
      "number of input HTTP client body bytes to scan (-1 unlimited)" },

    { "http_param_threshold", Parameter::PT_REAL, "0:1", "0.95",
      "alert threshold for http_param_model" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap snort_ml_rules[] =
{
    { SNORT_ML_SID, "potential threat found in HTTP parameters via Neural Network Based Exploit Detection" },
    { 0, nullptr }
};

static const PegInfo peg_names[] =
{
    { CountType::SUM, "uri_alerts", "total number of alerts triggered on HTTP URI" },
    { CountType::SUM, "client_body_alerts", "total number of alerts triggered on HTTP client body" },
    { CountType::SUM, "uri_bytes", "total number of HTTP URI bytes processed" },
    { CountType::SUM, "client_body_bytes", "total number of HTTP client body bytes processed" },
    { CountType::SUM, "libml_calls", "total libml calls" },
    { CountType::END, nullptr, nullptr }
};

#ifdef DEBUG_MSGS
static const TraceOption snort_ml_trace_options[] =
{
    { "classifier", TRACE_CLASSIFIER, "enable Snort ML classifier trace logging" },
    { nullptr, 0, nullptr }
};
#endif

//--------------------------------------------------------------------------
// module
//--------------------------------------------------------------------------

SnortMLModule::SnortMLModule() : Module(SNORT_ML_NAME, SNORT_ML_HELP, snort_ml_params) {}

bool SnortMLModule::set(const char*, Value& v, SnortConfig*)
{
    static_assert(std::is_same<decltype((Field().length())), decltype(conf.uri_depth)>::value,
        "Field::length maximum value should not exceed uri_depth type range");
    static_assert(std::is_same<decltype((Field().length())), decltype(conf.client_body_depth)>::value,
        "Field::length maximum value should not exceed client_body_depth type range");

    if (v.is("uri_depth"))
        conf.uri_depth = v.get_int32();
    else if (v.is("client_body_depth"))
        conf.client_body_depth = v.get_int32();
    else if (v.is("http_param_threshold"))
        conf.http_param_threshold = v.get_real();

    return true;
}

bool SnortMLModule::end(const char*, int, snort::SnortConfig*)
{
    if (!conf.uri_depth && !conf.client_body_depth)
        ParseWarning(WARN_CONF,
            "Neither of snort_ml source depth is set, snort_ml won't process traffic.");

    return true;
}

const RuleMap* SnortMLModule::get_rules() const
{ return snort_ml_rules; }

const PegInfo* SnortMLModule::get_pegs() const
{ return peg_names; }

PegCount* SnortMLModule::get_counts() const
{ return (PegCount*)&snort_ml_stats; }

ProfileStats* SnortMLModule::get_profile() const
{ return &snort_ml_prof; }

void SnortMLModule::set_trace(const Trace* trace) const
{ snort_ml_trace = trace; }

const TraceOption* SnortMLModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    return snort_ml_trace_options;
#endif
}
