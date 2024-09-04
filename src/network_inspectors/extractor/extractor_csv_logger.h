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
// csv_logger.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_CSV_LOGGER_H
#define EXTRACTOR_CSV_LOGGER_H

#include "framework/value.h"

#include "extractor_logger.h"
#include "extractor_writer.h"

class CsvExtractorLogger : public ExtractorLogger
{
public:
    CsvExtractorLogger(OutputType o_type, const std::vector<std::string>& fields)
        : ExtractorLogger(fields), writer(ExtractorWriter::make_writer(o_type))
    {
        if (writer)
            CsvExtractorLogger::add_header();
    }

    ~CsvExtractorLogger() override;

    void add_header() override;
    void add_field(const char*, const snort::Value&) override;
    void open_record() override;
    void close_record() override;

private:
    ExtractorWriter* const writer;
};

#endif
