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
// pps_rpc_decode.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class RpcDecode : public ConversionState
{
public:
    RpcDecode(Converter& c);
    ~RpcDecode() override;
    bool convert(std::istringstream& data_stream) override;

private:
    bool converted_args;
};
} // namespace

RpcDecode::RpcDecode(Converter& c) : ConversionState(c)
{
    converted_args = false;
}

RpcDecode::~RpcDecode()
{
    if (!converted_args)
    {
        auto& bind = cv.make_binder();
        bind.set_when_proto("tcp");
        bind.add_when_port("111");
        bind.add_when_port("32271");
        bind.set_use_type("rpc_decode");

        table_api.open_table("rpc_decode");
        table_api.close_table();
    }
}

bool RpcDecode::convert(std::istringstream& data_stream)
{
    bool retval = true;
    bool ports_set = false;
    std::string keyword;

    // adding the binder entry
    auto& bind = cv.make_binder();
    bind.set_when_proto("tcp");
    bind.set_use_type("rpc_decode");

    table_api.open_table("rpc_decode");

    while (data_stream >> keyword)
    {
        if (keyword == "no_alert_multiple_requests")
            table_api.add_deleted_comment("no_alert_multiple_requests");

        else if (keyword == "alert_fragments")
            table_api.add_deleted_comment("alert_fragments");

        else if (keyword == "no_alert_large_fragments")
            table_api.add_deleted_comment("no_alert_large_fragments");

        else if (keyword == "no_alert_incomplete")
            table_api.add_deleted_comment("no_alert_incomplete");

        else if (isdigit(keyword[0]))
        {
            bind.add_when_port(keyword);
            ports_set = true;
        }
        else
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    if (!ports_set)
    {
        bind.add_when_port("111");
        bind.add_when_port("32271");
    }

    converted_args = true;
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new RpcDecode(c); }

static const ConvertMap preprocessor_rpc_decode =
{
    "rpc_decode",
    ctor,
};

const ConvertMap* rpc_decode_map = &preprocessor_rpc_decode;
} // namespace preprocessors

