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
// extractor_services.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_service.h"

#include "log/messages.h"

#include "extractor.h"
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

ExtractorService::ExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, const ServiceBlueprint& srv_bp, ServiceType s_type,
    FormatType f_type, OutputType o_type, Extractor& ins) : tenant_id(tenant), inspector(ins), sbp(srv_bp), type(s_type)
{
    add_fields(srv_fields);
    add_events(srv_events);
    logger = ExtractorLogger::make_logger(f_type, o_type);
}

ExtractorService::~ExtractorService()
{
    for (auto h : handlers)
        delete h;

    delete logger;
}

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

ExtractorService* ExtractorService::make_service(Extractor& ins, const ServiceConfig& cfg,
    FormatType f_type, OutputType o_type)
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
        srv = new HttpExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, f_type, o_type, ins);
        break;

    case ServiceType::FTP:
        srv = new FtpExtractorService(cfg.tenant_id, cfg.fields, cfg.on_events, cfg.service, f_type, o_type, ins);
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

HttpExtractorService::HttpExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, FormatType f_type, OutputType o_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, f_type, o_type, ins)
{
    if (!logger)
        return;

    for (const auto& event : get_events())
    {
        ExtractorEvent* eh;

        if (!strcmp("eot", event.c_str()))
            eh = new HttpExtractor(ins, *logger, tenant_id, get_fields());

        else
            continue;

        auto names = eh->get_field_names();
        logger->set_fields(names);
        logger->add_header();
        handlers.push_back(eh);
    }
}

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

FtpExtractorService::FtpExtractorService(uint32_t tenant, const std::vector<std::string>& srv_fields,
    const std::vector<std::string>& srv_events, ServiceType s_type, FormatType f_type, OutputType o_type, Extractor& ins)
    : ExtractorService(tenant, srv_fields, srv_events, blueprint, s_type, f_type, o_type, ins)
{
    if (!logger)
        return;

    for (const auto& event : get_events())
    {
        ExtractorEvent* eh;

        if (!strcmp("request", event.c_str()))
            eh = new FtpRequestExtractor(ins, *logger, tenant_id, get_fields());

        else if (!strcmp("response", event.c_str()))
            eh = new FtpResponseExtractor(ins, *logger, tenant_id, get_fields());

        else if (!strcmp("eot", event.c_str()))
            eh = new FtpExtractor(ins, *logger, tenant_id, get_fields());

        else
            continue;

        auto names = eh->get_field_names();
        logger->set_fields(names);
        logger->add_header();
        handlers.push_back(eh);
    }
}

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
        ServiceType undef = ServiceType::UNDEFINED;
        ServiceType max = ServiceType::MAX;

        CHECK_FALSE(strcmp("http", http.c_str()));
        CHECK_FALSE(strcmp("ftp", ftp.c_str()));
        CHECK_FALSE(strcmp("(not set)", undef.c_str()));
        CHECK_FALSE(strcmp("(not set)", max.c_str()));
    }
}

#endif
