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
// extractor_logger.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_logger.h"

#include <cassert>

#include "log/messages.h"
#include "main/thread.h"
#include "managers/connector_manager.h"

#include "extractor_csv_logger.h"
#include "extractor_json_logger.h"

using namespace snort;

Connector* ExtractorLogger::get_connector(const std::string& conn_name)
{
    Connector* connector = ConnectorManager::get_connector(conn_name);

    if (connector == nullptr)
    {
        ErrorMessage("Unable to get '%s' connector in thread %d, fallback to default\n",
            conn_name.c_str(), get_instance_id());

        static ExtractorNullConnector default_connector;

        return &default_connector;
    }

    switch (connector->get_connector_direction())
    {
    case Connector::CONN_DUPLEX:
    case Connector::CONN_TRANSMIT:
        return connector;

    case Connector::CONN_RECEIVE:
    case Connector::CONN_UNDEFINED:
    default:
        break;
    }

    return nullptr;
}

ExtractorLogger* ExtractorLogger::make_logger(FormatType f_type, const std::string& conn_name, TimeType ts_type)
{
    ExtractorLogger* logger = nullptr;

    Connector* output_conn = get_connector(conn_name);

    assert(output_conn);

    switch (f_type)
    {
    case FormatType::CSV:
        logger = new CsvExtractorLogger(output_conn, ts_type);
        break;
    case FormatType::JSON:
        logger = new JsonExtractorLogger(output_conn, ts_type);
        break;
    case FormatType::MAX: // fallthrough
    default:
        break;
    }

    assert(logger);

    return logger;
}

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include <memory.h>

TEST_CASE("Format Type", "[extractor]")
{
    SECTION("to string")
    {
        FormatType csv = FormatType::CSV;
        FormatType json = FormatType::JSON;
        FormatType max = FormatType::MAX;

        CHECK_FALSE(strcmp("csv", csv.c_str()));
        CHECK_FALSE(strcmp("json", json.c_str()));
        CHECK_FALSE(strcmp("(not set)", max.c_str()));
    }
}

#endif
