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
// extractor_logger.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_LOGGER_H
#define EXTRACTOR_LOGGER_H

#include <sys/time.h>
#include <vector>

#include "framework/connector.h"
#include "sfip/sf_ip.h"

#include "extractor_null_conn.h"
#include "extractor_enums.h"

class ExtractorLogger
{
public:
    static ExtractorLogger* make_logger(FormatType, const std::string&);

    ExtractorLogger(snort::Connector* conn) : output_conn(conn)
    { }

    ExtractorLogger(const ExtractorLogger&) = delete;
    ExtractorLogger& operator=(const ExtractorLogger&) = delete;
    ExtractorLogger(ExtractorLogger&&) = delete;
    virtual ~ExtractorLogger() = default;

    virtual bool is_strict() const
    { return false; }

    virtual void add_header(const std::vector<const char*>&, const snort::Connector::ID&) {}
    virtual void add_footer(const snort::Connector::ID&) {}

    virtual void add_field(const char*, const char*) {}
    virtual void add_field(const char*, const char*, size_t) {}
    virtual void add_field(const char*, uint64_t) {}
    virtual void add_field(const char*, struct timeval) {}
    virtual void add_field(const char*, const snort::SfIp&) {}
    virtual void add_field(const char*, bool) {}

    const snort::Connector::ID get_id(const char* service_name) const
    { return output_conn->get_id(service_name); }

    virtual void open_record() {}
    virtual void close_record(const snort::Connector::ID&) {}
    void flush() { output_conn->flush(); }

protected:
    static snort::Connector* get_connector(const std::string& conn_name);

    snort::Connector* const output_conn;
};

#endif
