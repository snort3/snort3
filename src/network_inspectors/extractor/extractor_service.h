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
// extractor_service.h author Maya Dagon <mdagon@cisco.com>

#ifndef EXTRACTOR_SERVICE_H
#define EXTRACTOR_SERVICE_H

#include <algorithm>
#include <string>
#include <vector>

#include "framework/connector.h"

#include "extractor_enums.h"
#include "extractor_logger.h"

class Extractor;
class ServiceConfig;

class ExtractorEvent;

struct ServiceBlueprint
{
    std::vector<std::string> supported_events;
    std::vector<std::string> supported_fields;
};

class ExtractorService
{
public:
    static ExtractorService* make_service(Extractor&, const ServiceConfig&);

    ExtractorService() = delete;
    ExtractorService(const ExtractorService&) = delete;
    ExtractorService& operator=(const ExtractorService&) = delete;
    ExtractorService(ExtractorService&&) = delete;
    virtual ~ExtractorService();

    void show(std::string&) const;
    void tinit(ExtractorLogger* logger);
    void tterm();

    uint32_t get_tenant() const { return tenant_id; }
    const std::vector<std::string>& get_events() const { return events; }
    const std::vector<std::string>& get_fields() const { return fields; }

protected:
    ExtractorService(uint32_t tenant, const std::vector<std::string>& fields, const std::vector<std::string>& events,
        const ServiceBlueprint& srv_bp, ServiceType, Extractor& ins);

    virtual const snort::Connector::ID& internal_tinit() = 0;
    virtual const snort::Connector::ID& get_log_id() = 0;

    void add_events(const std::vector<std::string>& vals);
    void add_fields(const std::vector<std::string>& vals);
    bool find_event(const std::string&) const;
    bool find_field(const std::string&) const;

    static std::vector<std::string> common_fields;

    const uint32_t tenant_id;
    std::vector<std::string> fields;
    std::vector<std::string> events;

    Extractor& inspector;
    std::vector<ExtractorEvent*> handlers;
    static THREAD_LOCAL ExtractorLogger* logger;

    const ServiceBlueprint& sbp;
    const ServiceType type;
};

class HttpExtractorService : public ExtractorService
{
public:
    HttpExtractorService(uint32_t tenant, const std::vector<std::string>& fields,
        const std::vector<std::string>& events, ServiceType, Extractor&);

private:
    const snort::Connector::ID& internal_tinit() override;
    const snort::Connector::ID& get_log_id() override;

    static ServiceBlueprint blueprint;
    static THREAD_LOCAL snort::Connector::ID log_id;
};

class FtpExtractorService : public ExtractorService
{
public:
    FtpExtractorService(uint32_t tenant, const std::vector<std::string>& fields,
        const std::vector<std::string>& events, ServiceType, Extractor&);

private:
    const snort::Connector::ID& internal_tinit() override;
    const snort::Connector::ID& get_log_id() override;

    static ServiceBlueprint blueprint;
    static THREAD_LOCAL snort::Connector::ID log_id;
};

#endif

