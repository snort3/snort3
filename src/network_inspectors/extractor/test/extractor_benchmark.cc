//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor_benchmark.cc author Cisco

#ifdef BENCHMARK_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include <vector>

#include "network_inspectors/extractor/extractor_csv_logger.h"
#include "network_inspectors/extractor/extractor_json_logger.h"
#include "network_inspectors/extractor/extractor_null_conn.h"
#include "main/snort_config.h"

namespace snort
{
void ErrorMessage(const char*, ...) {}
SnortConfig::SnortConfig(snort::SnortConfig const*, char const*) { thiszone = 0; }
SnortConfig::~SnortConfig() { }
const SnortConfig* SnortConfig::get_conf() { static SnortConfig s_config; return &s_config; }
}

using namespace snort;
using namespace std;

#define FIELD_STRING                            \
    do                                          \
    {                                           \
        BENCHMARK("string")                     \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, str);       \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_SUB_STRING                        \
    do                                          \
    {                                           \
        BENCHMARK("sub-string")                 \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, str, 16);   \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_NUMBER                            \
    do                                          \
    {                                           \
        BENCHMARK("number")                     \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, num);       \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_TIMESTAMP                         \
    do                                          \
    {                                           \
        BENCHMARK("timestamp")                  \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, ts);        \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_SFIP                              \
    do                                          \
    {                                           \
        BENCHMARK("IP")                         \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, ip);        \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_BOOLEAN                           \
    do                                          \
    {                                           \
        BENCHMARK("boolean")                    \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, flag);      \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_STRING_VECTOR                     \
    do                                          \
    {                                           \
        BENCHMARK("string vector (x4)")         \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, v4_str);    \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_NUMBER_VECTOR                     \
    do                                          \
    {                                           \
        BENCHMARK("number vector (x4)")         \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, v4_num);    \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_BOOLEAN_VECTOR                    \
    do                                          \
    {                                           \
        BENCHMARK("boolean vector (x4)")        \
        {                                       \
            logger.open_record();               \
            logger.add_field(field, v4_flag);   \
            return true;                        \
        };                                      \
    } while (0)

#define FIELD_ALL                                       \
    do                                                  \
    {                                                   \
        BENCHMARK("record (all fields, no vectors)")    \
        {                                               \
            logger.open_record();                       \
            logger.add_field(field, str);               \
            logger.add_field(field, str, 16);           \
            logger.add_field(field, num);               \
            logger.add_field(field, ts);                \
            logger.add_field(field, ip);                \
            logger.add_field(field, flag);              \
            logger.close_record(id);                    \
            return true;                                \
        };                                              \
    } while (0)

#define FIELD_NONE                                      \
    do                                                  \
    {                                                   \
        BENCHMARK("empty record (no fields)")           \
        {                                               \
            logger.open_record();                       \
            logger.close_record(id);                    \
            return true;                                \
        };                                              \
    } while (0)

#define SEQUENCE                                                        \
    do {                                                                \
        const char* str = "0123456789abcdef";                           \
        uint64_t num = 0x12345678abcdef00;                              \
        struct timeval ts{};                                            \
        SfIp ip{};                                                      \
        bool flag = false;                                              \
        vector<const char*> v4_str = {"0123456789abcdef", "0123456789abcdef", "0123456789abcdef", "0123456789abcdef"}; \
        vector<uint64_t> v4_num = {0x12345678abcdef00, 0x12345678abcdef00, 0x12345678abcdef00, 0x12345678abcdef00}; \
        vector<bool> v4_flag = {false, true, false, true};              \
                                                                        \
        FIELD_STRING;                                                   \
        FIELD_SUB_STRING;                                               \
        FIELD_NUMBER;                                                   \
        FIELD_TIMESTAMP;                                                \
        FIELD_SFIP;                                                     \
        FIELD_BOOLEAN;                                                  \
        FIELD_STRING_VECTOR;                                            \
        FIELD_NUMBER_VECTOR;                                            \
        FIELD_BOOLEAN_VECTOR;                                           \
        FIELD_ALL;                                                      \
        FIELD_NONE;                                                     \
    } while (0)


TEST_CASE("CSV", "[Extractor]")
{
    ExtractorNullConnector nil;
    CsvExtractorLogger logger(&nil, TimeType());
    const Connector::ID& id = logger.get_id("");
    const char* field = "test";

    SEQUENCE;
}

TEST_CASE("TSV", "[Extractor]")
{
    ExtractorNullConnector nil;
    CsvExtractorLogger logger(&nil, TimeType(), '\t');
    const Connector::ID& id = logger.get_id("");
    const char* field = "test";

    SEQUENCE;
}

TEST_CASE("JSON", "[Extractor]")
{
    ExtractorNullConnector nil;
    JsonExtractorLogger logger(&nil, TimeType());
    const Connector::ID& id = logger.get_id("");
    const char* field = "test";

    SEQUENCE;
}

#endif
