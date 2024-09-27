//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// js_norm_module.cc author Danylo Kyrylov <dkyrylov@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_norm_module.h"

#include "trace/trace.h"

#include "js_config.h"
#include "js_enum.h"

using namespace jsn;
using namespace snort;

static constexpr char s_name[] = "js_norm";
static constexpr char s_help[] = "JavaScript normalizer";

THREAD_LOCAL const Trace* js_trace = nullptr;

THREAD_LOCAL PegCount JSNormModule::peg_counts[PEG_COUNT_MAX] = {};
THREAD_LOCAL ProfileStats JSNormModule::profile_stats;

static const Parameter ident_ignore_param[] =
{
    { "ident_name", Parameter::PT_STRING, nullptr, nullptr, "name of the identifier to ignore" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter prop_ignore_param[] =
{
    { "prop_name", Parameter::PT_STRING, nullptr, nullptr, "name of the object property to ignore" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const Parameter JSNormModule::params[] =
{
    { "bytes_depth", Parameter::PT_INT, "-1:max53", "-1",
      "number of input JavaScript bytes to normalize (-1 unlimited)" },

    { "identifier_depth", Parameter::PT_INT, "0:65536", "65536",
      "max number of unique JavaScript identifiers to normalize" },

    { "max_tmpl_nest", Parameter::PT_INT, "0:255", "32",
      "maximum depth of template literal nesting that enhanced JavaScript normalizer will process" },

    { "max_bracket_depth", Parameter::PT_INT, "1:65535", "256",
      "maximum depth of bracket nesting that enhanced JavaScript normalizer will process" },

    { "max_scope_depth", Parameter::PT_INT, "1:65535", "256",
      "maximum depth of scope nesting that enhanced JavaScript normalizer will process" },

    { "pdf_max_dictionary_depth", Parameter::PT_INT, "1:65535", "32",
      "maximum depth of dictionary nesting that PDF parser will process" },

    { "ident_ignore", Parameter::PT_LIST, ident_ignore_param, nullptr,
      "list of JavaScript ignored identifiers which will not be normalized" },

    { "prop_ignore", Parameter::PT_LIST, prop_ignore_param, nullptr,
      "list of JavaScript ignored object properties which will not be normalized" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const TraceOption trace_options[] =
{
    { "proc", TRACE_PROC, "enable processing logging" },
    { "dump", TRACE_DUMP, "enable data logging" },
#ifdef DEBUG_MSGS
    { "pdf_proc", TRACE_PDF_PROC, "enable processing logging for PDF extractor" },
    { "pdf_dump", TRACE_PDF_DUMP, "enable data logging for PDF extractor" },
#endif
    { nullptr, 0, nullptr }
};

const PegInfo JSNormModule::peg_names[PEG_COUNT_MAX + 1] =
{
    { CountType::SUM, "bytes", "total number of bytes processed" },
    { CountType::SUM, "identifiers", "total number of unique identifiers processed" },
    { CountType::SUM, "identifier_overflows", "total number of unique identifier limit overflows" },
    { CountType::END, nullptr, nullptr }
};

const RuleMap JSNormModule::events[] =
{
    { EVENT_NEST_UNESCAPE_FUNC, "nested unescape functions" },
    { EVENT_MIXED_UNESCAPE_SEQUENCE, "mixed unescape sequence" },
    { EVENT_BAD_TOKEN, "bad token" },
    { EVENT_OPENING_TAG, "unexpected HTML script opening tag" },
    { EVENT_CLOSING_TAG, "unexpected HTML script closing tag" },
    { EVENT_IDENTIFIER_OVERFLOW, "max number of unique identifiers reached" },
    { EVENT_BRACKET_NEST_OVERFLOW, "excessive bracket nesting" },
    { EVENT_DATA_LOST, "data gaps during normalization" },
    { EVENT_SCOPE_NEST_OVERFLOW, "excessive scope nesting" },
    { 0, nullptr }
};

JSNormModule::JSNormModule() : Module(s_name, s_help, params), config(nullptr)
{ }

JSNormModule::~JSNormModule()
{ }

bool JSNormModule::begin(const char* fqn, int, SnortConfig*)
{
    if (strcmp(s_name, fqn))
        return true;

    auto policy = get_inspection_policy();
    assert(policy);

    delete policy->jsn_config;
    policy->jsn_config = new JSNormConfig;
    config = policy->jsn_config;

    return true;
}

bool JSNormModule::set(const char*, Value& v, SnortConfig*)
{
    assert(config);

    if (v.is("bytes_depth"))
    {
        config->bytes_depth = v.get_int64();
    }
    else if (v.is("identifier_depth"))
    {
        config->identifier_depth = v.get_int32();
    }
    else if (v.is("max_tmpl_nest"))
    {
        config->max_template_nesting = v.get_uint8();
    }
    else if (v.is("max_bracket_depth"))
    {
        config->max_bracket_depth = v.get_uint32();
    }
    else if (v.is("max_scope_depth"))
    {
        config->max_scope_depth = v.get_uint32();
    }
    else if (v.is("ident_name"))
    {
        config->ignored_ids.insert(v.get_string());
    }
    else if (v.is("prop_name"))
    {
        config->ignored_props.insert(v.get_string());
    }
    else if (v.is("pdf_max_dictionary_depth"))
    {
        config->pdf_max_dictionary_depth = v.get_uint32();
    }

    return true;
}

void JSNormModule::set_trace(const Trace* trace) const
{
    js_trace = trace;
}

const TraceOption* JSNormModule::get_trace_options() const
{
    return trace_options;
}

unsigned JSNormModule::get_gid() const
{
    return js_gid;
}
