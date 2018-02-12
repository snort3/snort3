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
// config_one_string_options.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class ConfigStringOption : public ConversionState
{
public:
    ConfigStringOption(Converter& c,
        const std::string* snort_opt,
        const std::string* table,
        const std::string* lua_opt,
        bool string_array) :
        ConversionState(c),
        snort_option(snort_opt),
        lua_table(table),
        lua_option(lua_opt),
        use_string_array(string_array)
    {
    }


    bool convert(std::istringstream& stream) override
    {
        if ((snort_option == nullptr) ||
            (snort_option->empty()) ||
            (lua_table == nullptr) ||
            (lua_table->empty()))
        {
            return false;
        }

        // get length (stringstream will not read spaces...which we want)
        std::string arg_s = util::get_remain_data(stream);

        if (arg_s.empty())
        {
            data_api.failed_conversion(stream, "<missing_argument>");
            return false;
        }

        table_api.open_table(*lua_table);

        if ((lua_option != nullptr) && *snort_option != *lua_option)
        {
            table_api.add_diff_option_comment("config " + *snort_option +
                ":", *lua_option);
            if (use_string_array)
            {
                table_api.open_table(*lua_option);
                table_api.add_option(arg_s);
                table_api.close_table();
            }
            else
                table_api.add_option(*lua_option, arg_s);
        }
        else
        {
            if (use_string_array)
            {
                table_api.open_table(*snort_option);
                table_api.add_option(arg_s);
                table_api.close_table();
            }
            else
                table_api.add_option(*snort_option, arg_s);
        }

        table_api.close_table();
        stream.setstate(std::ios::eofbit); // done parsing this line
        return true;
    }

private:
    const std::string* snort_option;
    const std::string* lua_table;
    const std::string* lua_option;
    bool use_string_array;
};

template<const std::string* snort_option,
const std::string* lua_table,
const std::string* lua_option = nullptr,
bool use_string_array = false>
static ConversionState* config_string_ctor(Converter& c)
{
    return new ConfigStringOption(c, snort_option, lua_table, lua_option, use_string_array);
}
} // namespace

/*************************************************
 *****************  STRUCT_NAMES  ****************
 *************************************************/

static const std::string alerts = "alerts";
static const std::string daq = "daq";
static const std::string mode = "mode";
static const std::string packets = "packets";
static const std::string process = "process";
static const std::string react = "react";
static const std::string output = "output";

/*************************************************
 *******************  bpf_file  ******************
 *************************************************/

static const std::string bpf_file = "bpf_file";
static const ConvertMap bpf_file_api =
{
    bpf_file,
    config_string_ctor<& bpf_file, & packets>,
};

const ConvertMap* bpf_file_map = &bpf_file_api;

/*************************************************
 ********************  chroot  *******************
 *************************************************/

static const std::string chroot = "chroot";
static const ConvertMap chroot_api =
{
    chroot,
    config_string_ctor<& chroot, & process>,
};

const ConvertMap* chroot_map = &chroot_api;

/*************************************************
 *********************  daq  *********************
 *************************************************/

static const std::string module = "module";
static const ConvertMap daq_api =
{
    daq,
    config_string_ctor<& daq, & daq, & module>,
};

const ConvertMap* daq_map = &daq_api;

/*************************************************
 *******************  daq_dir  *******************
 *************************************************/

static const std::string daq_dir = "daq_dir";
static const std::string module_dirs = "module_dirs";
static const ConvertMap daq_dir_api =
{
    daq_dir,
    config_string_ctor<& daq_dir, & daq, & module_dirs, true>,
};

const ConvertMap* daq_dir_map = &daq_dir_api;

/*************************************************
 *******************  daq_var  *******************
 *************************************************/

static const std::string daq_var = "daq_var";
static const std::string variables = "variables";
static const ConvertMap daq_var_api =
{
    daq_var,
    config_string_ctor<& daq_var, & daq, & variables, true>,
};

const ConvertMap* daq_var_map = &daq_var_api;

/*************************************************
 *******************  logdir  ********************
 *************************************************/

static const std::string logdir = "logdir";
static const ConvertMap logdir_api =
{
    logdir,
    config_string_ctor<& logdir, & output>,
};

const ConvertMap* logdir_map = &logdir_api;

/*************************************************
 ********************  react  ********************
 *************************************************/

static const std::string page = "page";
static const ConvertMap react_api =
{
    react,
    config_string_ctor<& react, & react, & page>,
};

const ConvertMap* react_map = &react_api;

/*************************************************
 ****************  reference_net  ****************
 *************************************************/

static const std::string reference_net = "reference_net";
static const ConvertMap reference_net_api =
{
    reference_net,
    config_string_ctor<& reference_net, & alerts>,
};

const ConvertMap* reference_net_map = &reference_net_api;

/*************************************************
 *******************  set_gid  *******************
 *************************************************/

static const std::string set_gid = "set_gid";
static const ConvertMap set_gid_api =
{
    set_gid,
    config_string_ctor<& set_gid, & process>,
};

const ConvertMap* set_gid_map = &set_gid_api;

/*************************************************
 *******************  set_uid  ******************
 *************************************************/

static const std::string set_uid = "set_uid";
static const ConvertMap set_uid_api =
{
    set_uid,
    config_string_ctor<& set_uid, & process>,
};

const ConvertMap* set_uid_map = &set_uid_api;

/**************************************************
 ********************* umask  *********************
 **************************************************/

static const std::string umask = "umask";
static const ConvertMap umask_api =
{
    umask,
    config_string_ctor<& umask, & process>,
};

const ConvertMap* umask_map = &umask_api;
} // namespace config

