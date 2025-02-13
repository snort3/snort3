//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "main/reload_tuner.h"
#include "main/snort_config.h"
#include "managers/connector_manager.h"
#include "protocols/packet.h"

#include "extractors.h"
#include "extractor_logger.h"
#include "extractor_service.h"

using namespace snort;

THREAD_LOCAL ExtractorStats extractor_stats;
THREAD_LOCAL ProfileStats extractor_perf_stats;
THREAD_LOCAL ExtractorLogger* Extractor::logger = nullptr;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter extractor_proto_params[] =
{
    { "service", Parameter::PT_ENUM, "http | ftp | conn", nullptr,
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

    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "output destination for extractor" },

    { "default_filter", Parameter::PT_ENUM, "pick | skip", "pick",
      "default action for protocol with no filter provided" },

    { "protocols", Parameter::PT_LIST, extractor_proto_params, nullptr,
      "protocols to extract data" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

void ServiceConfig::clear()
{
    service = ServiceType::ANY;
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

    else if (v.is("connector"))
        extractor_config.output_conn = v.get_string();

    if (v.is("default_filter"))
        extractor_config.pick_by_default = v.get_uint8() == 0;

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

class ExtractorReloadSwapper : public ReloadSwapper
{
public:
    ExtractorReloadSwapper(Extractor& inspector) : inspector(inspector)
    { }

    void tswap() override
    {
        inspector.logger->flush();

        delete inspector.logger;
        inspector.logger = ExtractorLogger::make_logger(inspector.cfg.formatting, inspector.cfg.output_conn);

        for (auto& s : inspector.services)
            s->tinit(inspector.logger);
    }

private:
    Extractor& inspector;
};

Extractor::Extractor(ExtractorModule* m)
    : cfg(m->get_config())
{
    for (const auto& p : cfg.protocols)
        ExtractorService::validate(p);
}

Extractor::~Extractor()
{
    for (const auto& s : services)
        delete s;
}

bool Extractor::configure(SnortConfig* sc)
{
    assert(sc);
    snort_config = sc;

    for (const auto& p : cfg.protocols)
    {
        auto s = ExtractorService::make_service(*this, p);

        if (s)
            services.push_back(s);
    }

    Connector::Direction mode = ConnectorManager::is_instantiated(cfg.output_conn);

    if (mode != Connector::CONN_TRANSMIT and mode != Connector::CONN_DUPLEX)
    {
        ParseError("can't initialize extractor, cannot find Connector \"%s\" in transmit mode.\n",
            cfg.output_conn.c_str());
        return false;
    }

    return true;
}

void Extractor::show(const SnortConfig*) const
{
    ConfigLogger::log_value("formatting", cfg.formatting.c_str());
    ConfigLogger::log_value("connector", cfg.output_conn.c_str());
    ConfigLogger::log_value("pick_by_default", cfg.pick_by_default ? "pick" : "skip");

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

void Extractor::tinit()
{
    logger = ExtractorLogger::make_logger(cfg.formatting, cfg.output_conn);

    for (auto& s : services)
        s->tinit(logger);
}

void Extractor::tterm()
{
    for (auto& s : services)
        s->tterm();

    logger->flush();

    delete logger;
    logger = nullptr;
}

void Extractor::install_reload_handler(SnortConfig* sc)
{
    sc->register_reload_handler(new ExtractorReloadSwapper(*this));
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

