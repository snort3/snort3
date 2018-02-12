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
// kws_paths.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace keywords
{
namespace
{
template<const std::string* snort_option>
class Paths : public ConversionState
{
public:
    Paths(Converter& c) : ConversionState(c) { }

    bool convert(std::istringstream& data_stream) override
    {
        std::string arg1;
        std::string arg2;

        table_api.open_table("process");
        table_api.add_diff_option_comment(*snort_option, "plugin_path");
        table_api.add_comment("Since paths have changed between Snort and"
            "  Snort++, commenting out any plugin paths.  You must manually"
            " add them");

        if (!(data_stream >> arg1))
            return false;

        // this does not need to be set in conf file
        data_stream >> arg2;

        if (arg2.empty())
        {
            table_api.add_comment("Cannot add specific files to Snort++"
                " plugin path.  Use 'plugin_path = "
                "<dir>' instead of adding specific file: " + arg1);
        }
        else
        {
            if (arg1 == "directory")
                table_api.add_option("--plugin_path", arg2);

            else if (arg1 == "file")
                table_api.add_comment("Cannot add specific files to Snort++"
                    " plugin path.  Use 'plugin_path = "
                    "<dir>' instead of adding specific file: " + arg1);

            else
                return false;
        }

        return true;
    }
};

template<const std::string* snort_option>
static ConversionState* paths_ctor(Converter& c)
{ return new Paths<snort_option>(c); }
} // namespace

/**************************
 *******  A P I ***********
 **************************/

static const std::string dynamicengine = "dynamicengine";
static const std::string dynamicdetection = "dynamicdetection";
static const std::string dynamicsidechannel = "dynamicsidechannel";
static const std::string dynamicpreprocessor = "dynamicpreprocessor";

static const ConvertMap dynamicengine_api =
{
    dynamicengine,
    paths_ctor<& dynamicengine>,
};
static const ConvertMap dynamicdetection_api =
{
    dynamicdetection,
    paths_ctor<& dynamicdetection>,
};
static const ConvertMap dynamicsidechannel_api =
{
    dynamicsidechannel,
    paths_ctor<& dynamicsidechannel>,
};
static const ConvertMap dynamicpreprocessor_api =
{
    dynamicpreprocessor,
    paths_ctor<& dynamicpreprocessor>,
};

const ConvertMap* dynamicengine_map = &dynamicengine_api;
const ConvertMap* dynamicdetection_map = &dynamicdetection_api;
const ConvertMap* dynamicsidechannel_map = &dynamicsidechannel_api;
const ConvertMap* dynamicpreprocessor_map = &dynamicpreprocessor_api;
} // namespace keywords

