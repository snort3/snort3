/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// kws_paths.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"


namespace keywords
{

namespace {

template<const std::string *snort_option>
class Paths : public ConversionState
{
public:
    Paths( Converter* cv, LuaData* ld)
                            : ConversionState(cv, ld)
    {
    };

    virtual ~Paths() {};
    virtual bool convert(std::istringstream& data_stream)
    {
        std::string arg1;
        std::string arg2;

        ld->open_table("process");
        ld->add_diff_option_comment(*snort_option, "plugin_path");
        ld->add_comment_to_table("Since paths have changed between Snort and"
            "  Snort++, commenting out any plugin paths.  You must manually"
            " add them");

        if (!(data_stream >> arg1))
            return false;

        // this does not need to be set in conf file
        data_stream >> arg2;

        if (arg2.empty())
        {
            ld->add_comment_to_table("Cannot add specific files to Snort++"
                " plugin path.  Use 'plugin_path = "
                "<dir>' instead of adding specific file: " + arg1);
        }
        else
        {
            if (!arg1.compare("directory"))
                ld->add_option_to_table("--plugin_path", arg2);

            else if (!arg1.compare("file"))
                ld->add_comment_to_table("Cannot add specific files to Snort++"
                " plugin path.  Use 'plugin_path = "
                "<dir>' instead of adding specific file: " + arg1);

            else
                return false;
        }

        return true;
    }
};


template<const std::string *snort_option>
static ConversionState* paths_ctor(Converter* cv, LuaData* ld)
{
    return new Paths<snort_option>(cv, ld);
}

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
    paths_ctor<&dynamicengine>,
};
static const ConvertMap dynamicdetection_api =
{
    dynamicdetection,
    paths_ctor<&dynamicdetection>,
};
static const ConvertMap dynamicsidechannel_api =
{
    dynamicsidechannel,
    paths_ctor<&dynamicsidechannel>,
};
static const ConvertMap dynamicpreprocessor_api =
{
    dynamicpreprocessor,
    paths_ctor<&dynamicpreprocessor>,
};


const ConvertMap* dynamicengine_map = &dynamicengine_api;
const ConvertMap* dynamicdetection_map = &dynamicdetection_api;
const ConvertMap* dynamicsidechannel_map = &dynamicsidechannel_api;
const ConvertMap* dynamicpreprocessor_map = &dynamicpreprocessor_api;

} // namespace keywords
