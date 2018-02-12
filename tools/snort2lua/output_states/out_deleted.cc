//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// output_deleted.cc author Carter Waxman <cwaxman@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace output
{
namespace
{
class Deleted : public ConversionState
{
public:
    Deleted(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Deleted::convert(std::istringstream& data_stream)
{
    data_stream.setstate(std::ios::eofbit); // deleted, not failures
    return true;
}

template<const std::string* snort_option>
static ConversionState* deleted_ctor(Converter& c)
{
    // set here since not all deleted keywords have options
    if (!DataApi::is_quiet_mode())
    {
        c.get_table_api().open_table("deleted_snort_outputs");
        c.get_table_api().add_deleted_comment("output " + *snort_option + "[:.*]");
        c.get_table_api().close_table();
    }

    return new Deleted(c);
}

/*************************************************
 *************  sfalert_unified2 ****************
 *************************************************/

static const std::string sfalert_unified2 = "sfalert_unified2";
static const ConvertMap sfalert_unified2_api =
{
    sfalert_unified2,
    deleted_ctor<&sfalert_unified2>,
};

const ConvertMap* sfalert_unified2_map = &sfalert_unified2_api;

/*************************************************
 *************  sflog_unified2 ****************
 *************************************************/

static const std::string sflog_unified2 = "slog_unified2";
static const ConvertMap sflog_unified2_api =
{
    sflog_unified2,
    deleted_ctor<&sflog_unified2>,
};

const ConvertMap* sflog_unified2_map = &sflog_unified2_api;
} // namespace output
