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
// extractor_logger.cc author Anna Norokh <anorokh@cisco.com>

#include "extractor_logger.h"

#include "extractor_csv_logger.h"

ExtractorLogger* ExtractorLogger::make_logger(FormatType f_type, OutputType o_type,
    const std::vector<std::string>& fields)
{
    switch (f_type)
    {
    case FormatType::CSV:
        return new CsvExtractorLogger(o_type, fields);
    }

    return nullptr;
}
