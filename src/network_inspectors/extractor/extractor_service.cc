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
// extractor_service.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_service.h"

#include "log/messages.h"

#include "extractor.h"
#include "extractor_conn.h"
#include "extractor_detection.h"
#include "extractor_dns.h"
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
    "pkt_num",
    "tenant_id"
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
    }
}

void ExtractorService::add_fields(const std::vector<std::string>& vals)
{
    for (auto& val : vals)
    {
        if (find_field(val))
            fields.push_back(val);
    }
}

ExtractorService* ExtractorService::make_service(Extractor& ins, const ServiceConfig& cfg)
{
    if (cfg.on_events.empty())
    {
        ErrorMessage("Extractor: %s service misses on_events field\n", cfg.service.c_str());
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

    case ServiceType::DNS:
        srv = new DnsExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, ins);
        break;

    case ServiceType::IPS_BUILTIN:
        srv = new BuiltinExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, ins);
        break;

    case ServiceType::IPS_USER:
        srv = new IpsUserExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, ins);
        break;

    case ServiceType::ANY: // fallthrough
    default:
        ErrorMessage("Extractor: '%s' service is not supported\n", cfg.service.c_str());
    }

    return srv;
}

bool ExtractorService::find_event(const std::string& event) const
{
    return find_event(sbp, event);
}

bool ExtractorService::find_field(const std::string& field) const
{
    return find_field(sbp, field);
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

bool ExtractorService::find_event(const ServiceBlueprint& sbp, const std::string& event)
{
    return std::find(sbp.supported_events.begin(), sbp.supported_events.end(), event)
        != sbp.supported_events.end();
}

bool ExtractorService::find_field(const ServiceBlueprint& sbp, const std::string& field)
{
    return ((std::find(common_fields.begin(), common_fields.end(), field) != common_fields.end())
        or (std::find(sbp.supported_fields.begin(), sbp.supported_fields.end(),field)
        != sbp.supported_fields.end()));
}

void ExtractorService::validate_events(const ServiceBlueprint& sbp, const std::vector<std::string>& vals)
{
    for (const auto& val : vals)
    {
        if (!find_event(sbp, val))
            ParseError("unsupported '%s' event in protocols.on_events", val.c_str());
    }
}

void ExtractorService::validate_fields(const ServiceBlueprint& sbp, const std::vector<std::string>& vals)
{
    for (auto& val : vals)
    {
        if (!find_field(sbp, val))
            ParseError("unsupported '%s' field in protocols.fields\n", val.c_str());
    }
}

void ExtractorService::validate(const ServiceConfig& cfg)
{
    if (cfg.on_events.empty())
        ParseError("%s service misses on_events field", cfg.service.c_str());

    switch (cfg.service)
    {
    case ServiceType::HTTP:
        validate_events(HttpExtractorService::blueprint, cfg.on_events);
        validate_fields(HttpExtractorService::blueprint, cfg.fields);
        break;

    case ServiceType::FTP:
        validate_events(FtpExtractorService::blueprint, cfg.on_events);
        validate_fields(FtpExtractorService::blueprint, cfg.fields);
        break;

    case ServiceType::CONN:
        validate_events(ConnExtractorService::blueprint, cfg.on_events);
        validate_fields(ConnExtractorService::blueprint, cfg.fields);
        break;

    case ServiceType::DNS:
        validate_events(DnsExtractorService::blueprint, cfg.on_events);
        validate_fields(DnsExtractorService::blueprint, cfg.fields);
        break;

    case ServiceType::IPS_BUILTIN:
        validate_fields(BuiltinExtractorService::blueprint, cfg.fields);
        validate_events(BuiltinExtractorService::blueprint, cfg.on_events);
        break;

    case ServiceType::IPS_USER:
        validate_fields(IpsUserExtractorService::blueprint, cfg.fields);
        validate_events(IpsUserExtractorService::blueprint, cfg.on_events);
        break;

    case ServiceType::ANY: // fallthrough
    default:
        ParseError("'%s' service is not supported", cfg.service.c_str());
    }
}

//-------------------------------------------------------------------------
//  HttpExtractorService
//-------------------------------------------------------------------------

const ServiceBlueprint HttpExtractorService::blueprint =
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
      "resp_filenames",
      "orig_mime_types",
      "resp_mime_types"
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

const ServiceBlueprint FtpExtractorService::blueprint =
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

const ServiceBlueprint ConnExtractorService::blueprint =
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
        "duration",
        "orig_bytes",
        "resp_bytes",
        "history",
        "conn_state"
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
//  DnsExtractorService
//-------------------------------------------------------------------------

const ServiceBlueprint DnsExtractorService::blueprint =
{
    // events
    {
        "response",
    },
    // fields
    {
        "proto",
        "trans_id",
        "query",
        "qclass",
        "qclass_name",
        "qtype",
        "qtype_name",
        "rcode",
        "rcode_name",
        "AA",
        "TC",
        "RD",
        "RA",
        "Z",
        "answers",
        "TTLs",
        "rejected",
        "auth",
        "addl"
    },
};

THREAD_LOCAL Connector::ID DnsExtractorService::log_id;

DnsExtractorService::DnsExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, ins)
{
    for (const auto& event : get_events())
    {
        if (!strcmp("response", event.c_str()))
            handlers.push_back(new DnsResponseExtractor(ins, tenant_id, get_fields()));
    }
}

const snort::Connector::ID& DnsExtractorService::internal_tinit()
{ return log_id = logger->get_id(type.c_str()); }

const snort::Connector::ID& DnsExtractorService::get_log_id()
{ return log_id; }

//-------------------------------------------------------------------------
//  IpsUserExtractorService
//-------------------------------------------------------------------------

const ServiceBlueprint IpsUserExtractorService::blueprint =
{
    // events
    {
        "ips_logging",
        "context_logging",
    },
    // fields
    {
        "action",
        "sid",
        "gid",
        "rev",
        "msg",
        "refs",
        "proto",
        "source",
    },
};

THREAD_LOCAL Connector::ID IpsUserExtractorService::log_id;

IpsUserExtractorService::IpsUserExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, ins)
{
    for (const auto& event : get_events())
    {
        bool contextual = !strcmp("context_logging", event.c_str());
        if (contextual or !strcmp("ips_logging", event.c_str()))
            handlers.push_back(new IpsUserExtractor(ins, tenant_id, get_fields(), contextual));
    }
}

const snort::Connector::ID& IpsUserExtractorService::internal_tinit()
{ return log_id = logger->get_id(type.c_str()); }

const snort::Connector::ID& IpsUserExtractorService::get_log_id()
{ return log_id; }

//-------------------------------------------------------------------------
//  BuiltinExtractorService
//-------------------------------------------------------------------------

const ServiceBlueprint BuiltinExtractorService::blueprint =
{
    // events
    {
        "builtin",
    },
    // fields
    {
        "sid",
        "gid",
        "msg",
        "proto",
        "source",
    },
};

THREAD_LOCAL Connector::ID BuiltinExtractorService::log_id;

BuiltinExtractorService::BuiltinExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, ins)
{
    for (const auto& event : get_events())
    {
        if (!strcmp("builtin", event.c_str()))
            handlers.push_back(new BuiltinExtractor(ins, tenant_id, get_fields()));
    }
}

const snort::Connector::ID& BuiltinExtractorService::internal_tinit()
{ return log_id = logger->get_id(type.c_str()); }

const snort::Connector::ID& BuiltinExtractorService::get_log_id()
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
        ServiceType dns = ServiceType::DNS;
        ServiceType weird = ServiceType::IPS_BUILTIN;
        ServiceType notice = ServiceType::IPS_USER;
        ServiceType any = ServiceType::ANY;
        ServiceType max = ServiceType::MAX;

        CHECK_FALSE(strcmp("http", http.c_str()));
        CHECK_FALSE(strcmp("ftp", ftp.c_str()));
        CHECK_FALSE(strcmp("conn", conn.c_str()));
        CHECK_FALSE(strcmp("dns", dns.c_str()));
        CHECK_FALSE(strcmp("weird", weird.c_str()));
        CHECK_FALSE(strcmp("notice", notice.c_str()));
        CHECK_FALSE(strcmp("(not set)", any.c_str()));
        CHECK_FALSE(strcmp("(not set)", max.c_str()));
    }
}

#endif
