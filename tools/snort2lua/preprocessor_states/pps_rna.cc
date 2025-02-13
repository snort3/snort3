//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// pps_rna.cc author Masud Hasan <mashasan@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"

namespace preprocessors
{
    namespace
    {
        class Rna : public ConversionState
        {
        public:
            Rna(Converter& c) : ConversionState(c) { }
            bool convert(std::istringstream& data) override;
        };
    }

    bool Rna::convert(std::istringstream& data_stream)
    {
        bool retval = true;

        table_api.open_table("rna");

        std::string keyword;
        while (data_stream >> keyword)
        {
            bool tmpval = true;

            if (keyword == "rna_conf")
                tmpval = parse_string_option("rna_conf_path", data_stream);
            else if (keyword == "memcap")
            {
                int ignored_val;
                data_stream >> ignored_val;
            }
            else
                tmpval = false;

            if (!tmpval)
            {
                data_api.failed_conversion(data_stream, keyword);
                retval = false;
            }
        }

        return retval;
    }

    /**************************
     *******  A P I ***********
     **************************/

    static ConversionState* ctor(Converter& c)
    {
        return new Rna(c);
    }

    static const ConvertMap rna_api =
    {
        "rna",
        ctor,
    };

    const ConvertMap* rna_map = &rna_api;
} // namespace preprocessors
