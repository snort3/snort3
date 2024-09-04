//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// extractor.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor.h"

#include <algorithm>

#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "pub_sub/http_events.h"

#include "extractor_event_handlers.h"
#include "extractor_logger.h"
#include "extractor_service.h"

using namespace snort;

THREAD_LOCAL ExtractorStats extractor_stats;
THREAD_LOCAL ProfileStats extractor_perf_stats;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter extractor_proto_params[] =
{
    { "service", Parameter::PT_ENUM, "http", nullptr,
      "service to extract from" },

    { "tenant_id", Parameter::PT_INT, "0:max32", "0",
      "tenant_id of target tenant" },

    { "on_events", Parameter::PT_STRING, nullptr, nullptr,
      "specify events to log" },

    { "fields", Parameter::PT_STRING, nullptr, nullptr,
      "specify fields to log" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "formatting", Parameter::PT_ENUM, "csv | json", "csv",
      "output format for extractor" },

    { "output", Parameter::PT_ENUM, "stdout", "stdout",
      "output destination for extractor" },

    { "protocols", Parameter::PT_LIST, extractor_proto_params, nullptr,
      "protocols to extract data" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

void ServiceConfig::clear()
{
    service = ServiceType::UNDEFINED;
    on_events.clear();
    tenant_id = 0;
    fields.clear();
}

ExtractorModule::ExtractorModule() : Module(S_NAME, s_help, s_params) { }

void ExtractorModule::commit_config()
{
    for (const auto& p : extractor_config.protocols)
    {
        if (p.tenant_id == service_config.tenant_id and p.service == service_config.service)
            ParseWarning(WARN_CONF_STRICT, "%s service got multiple configurations", service_config.service.c_str());
    }

    extractor_config.protocols.push_back(service_config);
    service_config.clear();
}

static inline void trim(std::string& str)
{
    str.erase(str.find_last_not_of(' ') + 1);
    str.erase(0, str.find_first_not_of(' '));
}

void ExtractorModule::store(Value& val, std::vector<std::string>& dst)
{
    dst.clear();
    val.set_first_token();
    std::string tok;
    while (val.get_next_csv_token(tok))
    {
        trim(tok);
        dst.push_back(tok);
    }
}

bool ExtractorModule::begin(const char*, int idx, SnortConfig*)
{
    if (idx == 0)
    {
        service_config.clear();
        extractor_config.protocols.clear();
    }

    return true;
}

bool ExtractorModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("formatting"))
        extractor_config.formatting = (FormatType)(v.get_uint8());

    else if (v.is("output"))
        extractor_config.output = (OutputType)(v.get_uint8());

    else if (v.is("service"))
        service_config.service = (ServiceType)(v.get_uint8());

    else if (v.is("tenant_id"))
        service_config.tenant_id = v.get_uint32();

    else if (v.is("on_events"))
        store(v, service_config.on_events);

    else if (v.is("fields"))
        store(v, service_config.fields);

    return true;
}

bool ExtractorModule::end(const char* fqn, int idx, SnortConfig*)
{
    if (!idx or strcmp(fqn, "extractor.protocols"))
        return true;

    if (service_config.fields.empty())
    {
        ParseError("can't initialize extractor without protocols.fields");
        return false;
    }

    commit_config();

    return true;
}

//-------------------------------------------------------------------------
// Inspector stuff
//-------------------------------------------------------------------------

Extractor::Extractor(ExtractorModule* m)
{
    auto& cfg = m->get_config();

    format = cfg.formatting;
    output = cfg.output;

    for (const auto& p : cfg.protocols)
    {
        auto s = ExtractorService::make_service(p, format, output);

        if (s)
            services.push_back(s);
    }
}

Extractor::~Extractor()
{
    for (const auto& s : services)
        delete s;
}

void Extractor::show(const SnortConfig*) const
{
    ConfigLogger::log_value("formatting", format.c_str());
    ConfigLogger::log_value("output", output.c_str());

    bool log_header = true;
    for (const auto& s : services)
    {
        if (log_header)
        {
            ConfigLogger::log_option("protocols");
            log_header = false;
        }
        std::string str;
        s->show(str);

        ConfigLogger::log_list("", str.c_str(), "   ");
    }
}
//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ExtractorModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* extractor_ctor(Module* mod)
{ return new Extractor((ExtractorModule*)mod); }

static void extractor_dtor(Inspector* p)
{ delete p; }

static InspectApi extractor_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_TYPE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    extractor_ctor,
    extractor_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_extractor[] =
#endif
{
    &extractor_api.base,
    nullptr
};

