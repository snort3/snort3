//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// pps_sdf.cc author Victor Roemer <viroemer@cisco.com>

#include "conversion_state.h"
#include "data/dt_table_api.h"

namespace preprocessors
{
namespace
{
class Sdf : public ConversionState
{
public:
    Sdf(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override
    {
        std::string keyword;

        // skip over `preprocessor sensitive_data` because it is now a rule option.
        while (data_stream >> keyword)
        {
            if ( keyword == "mask_output")
            {
                table_api.open_table("output");
                table_api.add_option("obfuscate_pii", true);
                table_api.close_table();
            }
        }

        return true;
    }
};
} // namespace

static ConversionState* sdf_ctor(Converter& c)
{
    return new Sdf(c);
}

static const ConvertMap preprocessor_sdf =
{
    "sensitive_data",
    sdf_ctor,
};

const ConvertMap* sdf_map = &preprocessor_sdf;
} // namespace preprocessors

