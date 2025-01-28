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
// extractor_service.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_service.h"

#include "log/messages.h"

#include "extractor.h"
#include "extractor_conn.h"
#include "extractor_ftp.h"
#include "extractor_http.h"

using namespace snort;

//-------------------------------------------------------------------------
// ExtractorService
//-------------------------------------------------------------------------

std::vector<std::string> ExtractorService::common_fields =
{
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "pkt_num"
};

THREAD_LOCAL ExtractorLogger* ExtractorService::logger = nullptr;

ExtractorService::ExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, const ServiceBlueprint& srv_bp, ServiceType s_type,
    Extractor& ins) : tenant_id(tenant), inspector(ins), sbp(srv_bp), type(s_type)
{
    add_fields(srv_fields);
    add_events(srv_events);
}

ExtractorService::~ExtractorService()
{
    for (auto h : handlers)
        delete h;
}

void ExtractorService::tinit(ExtractorLogger* new_logger)
{
    assert(new_logger);

    logger = new_logger;

    const Connector::ID& service_id = internal_tinit();

    for (auto handler : handlers)
    {
        handler->tinit(logger, &service_id);
        logger->add_header(handler->get_field_names(), service_id);
    }
}

void ExtractorService::tterm()
{ logger->add_footer(get_log_id()); }

void ExtractorService::add_events(const std::vector<std::string>& vals)
{
    for (const auto& val : vals)
    {
        if (find_event(val))
            events.push_back(val);
        else
            ParseWarning(WARN_CONF_STRICT, "unsupported '%s' event in protocols.on_events", val.c_str());
    }
}

void ExtractorService::add_fields(const std::vector<std::string>& vals)
{
    for (auto& val : vals)
    {
        if (find_field(val))
            fields.push_back(val);
        else
            ParseWarning(WARN_CONF_STRICT, "unsupported '%s' field in protocols.fields", val.c_str());
    }
}

ExtractorService* ExtractorService::make_service(Extractor& ins, const ServiceConfig& cfg)
{
    if (cfg.on_events.empty())
    {
        ParseError("%s service misses on_events field", cfg.service.c_str());
        return nullptr;
    }

    ExtractorService* srv = nullptr;

    switch (cfg.service)
    {
    case ServiceType::HTTP:
        srv = new HttpExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, ins);
        break;

    case ServiceType::FTP:
        srv = new FtpExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, ins);
        break;

    case ServiceType::CONN:
        srv = new ConnExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, ins);
        break;

    case ServiceType::UNDEFINED: // fallthrough
    default:
        ParseError("'%s' service is not supported", cfg.service.c_str());
    }

    return srv;
}

bool ExtractorService::find_event(const std::string& event) const
{
    return std::find(sbp.supported_events.begin(), sbp.supported_events.end(), event)
        != sbp.supported_events.end();
}

bool ExtractorService::find_field(const std::string& field) const
{
    return ((std::find(common_fields.begin(), common_fields.end(), field) != common_fields.end()) or
        (std::find(sbp.supported_fields.begin(), sbp.supported_fields.end(),field)
          != sbp.supported_fields.end()));
}

void ExtractorService::show(std::string& str) const
{
    str = "{ service = ";
    str += type.c_str();
    str += ", tenant_id = ";
    str += std::to_string(tenant_id);
    str += ", on_events =";
    for (const auto& event : get_events())
    {
        str += " ";
        str += event;
    }
    str += ", fields = ";
    for (const auto& field : get_fields())
    {
        str += field;
        str += " ";
    }
    str += " }";
}

//-------------------------------------------------------------------------
//  HttpExtractorService
//-------------------------------------------------------------------------

ServiceBlueprint HttpExtractorService::blueprint =
{
    // events
    {
      "eot",
    },
    // fields
    {
      "method",
      "host",
      "uri",
      "user_agent",
      "referrer",
      "origin",
      "version",
      "status_code",
      "status_msg",
      "trans_depth",
      "request_body_len",
      "response_body_len",
      "info_code",
      "info_msg",
      "proxied",
      "orig_filenames",
      "resp_filenames"
    },
};

THREAD_LOCAL Connector::ID HttpExtractorService::log_id;

HttpExtractorService::HttpExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, ins)
{
    for (const auto& event : get_events())
    {
        if (!strcmp("eot", event.c_str()))
            handlers.push_back(new HttpExtractor(ins, tenant_id, get_fields()));
    }
}

const snort::Connector::ID& HttpExtractorService::internal_tinit()
{ return log_id = logger->get_id(type.c_str()); }

const snort::Connector::ID& HttpExtractorService::get_log_id()
{ return log_id; }

//-------------------------------------------------------------------------
//  FtpExtractorService
//-------------------------------------------------------------------------

ServiceBlueprint FtpExtractorService::blueprint =
{
    // events
    {
      "request",
      "response",
      "eot",
    },
    // fields
    {
      "command",
      "arg",
      "user",
      "reply_code",
      "reply_msg",
      "file_size",
      "data_channel.passive",
      "data_channel.orig_h",
      "data_channel.resp_h",
      "data_channel.resp_p"
    },
};

THREAD_LOCAL Connector::ID FtpExtractorService::log_id;

FtpExtractorService::FtpExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, ins)
{
    for (const auto& event : get_events())
    {
        if (!strcmp("request", event.c_str()))
            handlers.push_back(new FtpRequestExtractor(ins, tenant_id, get_fields()));
        else if (!strcmp("response", event.c_str()))
            handlers.push_back(new FtpResponseExtractor(ins, tenant_id, get_fields()));
        else if (!strcmp("eot", event.c_str()))
            handlers.push_back(new FtpExtractor(ins, tenant_id, get_fields()));
    }
}

const snort::Connector::ID& FtpExtractorService::internal_tinit()
{ return log_id = logger->get_id(type.c_str()); }

const snort::Connector::ID& FtpExtractorService::get_log_id()
{ return log_id; }

//-------------------------------------------------------------------------
//  ConnExtractorService
//-------------------------------------------------------------------------

ServiceBlueprint ConnExtractorService::blueprint =
{
    // events
    {
        "eof",
    },
    // fields
    {
        "proto",
        "service",
        "orig_pkts",
        "resp_pkts",
        "duration"
    },
};

THREAD_LOCAL Connector::ID ConnExtractorService::log_id;

ConnExtractorService::ConnExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, ins)
{
    for (const auto& event : get_events())
    {
        if (!strcmp("eof", event.c_str()))
            handlers.push_back(new ConnExtractor(ins, tenant_id, get_fields()));
    }
}

const snort::Connector::ID& ConnExtractorService::internal_tinit()
{ return log_id = logger->get_id(type.c_str()); }

const snort::Connector::ID& ConnExtractorService::get_log_id()
{ return log_id; }

//-------------------------------------------------------------------------
//  Unit Tests
//-------------------------------------------------------------------------

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include <memory.h>

TEST_CASE("Service Type", "[extractor]")
{
    SECTION("to string")
    {
        ServiceType http = ServiceType::HTTP;
        ServiceType ftp = ServiceType::FTP;
        ServiceType conn = ServiceType::CONN;
        ServiceType undef = ServiceType::UNDEFINED;
        ServiceType max = ServiceType::MAX;

        CHECK_FALSE(strcmp("http", http.c_str()));
        CHECK_FALSE(strcmp("ftp", ftp.c_str()));
        CHECK_FALSE(strcmp("conn", conn.c_str()));
        CHECK_FALSE(strcmp("(not set)", undef.c_str()));
        CHECK_FALSE(strcmp("(not set)", max.c_str()));
    }
}

#endif
