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
// config_one_string_options.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace config
{

namespace
{



template<const std::string* snort_option,
        const std::string* lua_table,
        const std::string* lua_option>
class ConfigStringOption : public ConversionState
{
public:
    ConfigStringOption( Converter* cv, LuaData* ld)
                            : ConversionState(cv, ld)
    {
    };

    virtual ~ConfigStringOption() {};
    virtual bool convert(std::istringstream& stream)
    {
        if (snort_option == nullptr ||
            lua_table == nullptr)
        {
            return false;
        }

        // get length (stringstream will not read spaces...which we want)
        const std::streamoff pos = stream.tellg();
        stream.seekg(0, stream.end);
        const std::streamoff length = stream.tellg() - pos;
        stream.seekg(pos);

        // read argument
        char *arg_c = new char[length + 1];
        stream.read(arg_c, length);
        arg_c[length] = '\0';
        std::string arg_s(arg_c);
        delete[] arg_c;
        util::trim(arg_s);


        bool retval;
        ld->open_table(*lua_table);

        if((lua_option != nullptr) && (*snort_option).compare(*lua_option))
        {
            ld->add_diff_option_comment("config " + *snort_option +
                ":", *lua_option);
            retval = ld->add_option_to_table(*lua_option, arg_s);
        }
        else
        {
            retval = ld->add_option_to_table(*snort_option, arg_s);
        }

        ld->close_table();
        return retval;
    }
};


template<const std::string *snort_option,
        const std::string *lua_table,
        const std::string *lua_option = nullptr>
static ConversionState* config_string_ctor(Converter* cv, LuaData* ld)
{
    return new ConfigStringOption<snort_option,
                                lua_table,
                                lua_option>(cv, ld);
}

} // namespace

/*************************************************
 *****************  STRUCT_NAMES  ****************
 *************************************************/

static const std::string active = "active";
static const std::string alerts = "alerts";
static const std::string daq = "daq";
static const std::string ips = "ips";
static const std::string mode = "mode";
static const std::string packets = "packets";
static const std::string process = "process";
static const std::string output = "output";



/*************************************************
 ******************  alert_file  *****************
 *************************************************/

static const std::string alertfile = "alertfile";
static const std::string alert_file = "alert_file";
static const ConvertMap alertfile_api =
{
    alertfile,
    config_string_ctor<&alertfile, &alerts, &alert_file>,
};

const ConvertMap* alertfile_map = &alertfile_api;

/*************************************************
 *******************  bpf_file  ******************
 *************************************************/

static const std::string bpf_file = "bpf_file";
static const ConvertMap bpf_file_api =
{
    bpf_file,
    config_string_ctor<&bpf_file, &packets>,
};

const ConvertMap* bpf_file_map = &bpf_file_api;

/*************************************************
 ********************  chroot  *******************
 *************************************************/

static const std::string chroot = "chroot";
static const ConvertMap chroot_api =
{
    chroot,
    config_string_ctor<&chroot, &process>,
};

const ConvertMap* chroot_map = &chroot_api;

/*************************************************
 *********************  daq  *********************
 *************************************************/

static const std::string name = "name";
static const ConvertMap daq_api =
{
    daq,
    config_string_ctor<&daq, &daq, &name>,
};

const ConvertMap* daq_map = &daq_api;

/*************************************************
 *******************  daq_dir  *******************
 *************************************************/

static const std::string daq_dir = "daq_dir";
static const std::string dir = "dir";
static const ConvertMap daq_dir_api =
{
    daq_dir,
    config_string_ctor<&daq_dir, &daq, &dir>,
};

const ConvertMap* daq_dir_map = &daq_dir_api;

/*************************************************
 *******************  daq_mode  *******************
 *************************************************/

static const std::string daq_mode = "daq_mode";
static const ConvertMap daq_mode_api =
{
    daq_mode,
    config_string_ctor<&daq_mode, &daq, &mode>,
};

const ConvertMap* daq_mode_map = &daq_mode_api;

/*************************************************
 *******************  daq_var  *******************
 *************************************************/

static const std::string daq_var = "daq_var";
static const std::string var = "var";
static const ConvertMap daq_var_api =
{
    daq_var,
    config_string_ctor<&daq_var, &daq, &var>,
};

const ConvertMap* daq_var_map = &daq_var_api;

/*************************************************
 *******************  logdir  ********************
 *************************************************/

static const std::string logdir = "logdir";
static const ConvertMap logdir_api =
{
    logdir,
    config_string_ctor<&logdir, &output>,
};

const ConvertMap* logdir_map = &logdir_api;

/*************************************************
 *****************  policy_mode  *****************
 *************************************************/

static const std::string policy_mode = "policy_mode";
static const ConvertMap policy_mode_api =
{
    policy_mode,
    config_string_ctor<&policy_mode, &ips, &mode>,
};

const ConvertMap* policy_mode_map = &policy_mode_api;

/*************************************************
 ********************  react  ********************
 *************************************************/

static const std::string react = "react";
static const ConvertMap react_api =
{
    react,
    config_string_ctor<&react, &active>,
};

const ConvertMap* react_map = &react_api;

/*************************************************
 ****************  reference_net  ****************
 *************************************************/

static const std::string reference_net = "reference_net";
static const ConvertMap reference_net_api =
{
    reference_net,
    config_string_ctor<&reference_net, &alerts>,
};

const ConvertMap* reference_net_map = &reference_net_api;

/*************************************************
 *******************  set_gid  *******************
 *************************************************/

static const std::string set_gid = "set_gid";
static const ConvertMap set_gid_api =
{
    set_gid,
    config_string_ctor<&set_gid, &process>,
};

const ConvertMap* set_gid_map = &set_gid_api;

/*************************************************
 *******************  set_uid  ******************
 *************************************************/

static const std::string set_uid = "set_uid";
static const ConvertMap set_uid_api =
{
    set_uid,
    config_string_ctor<&set_uid, &process>,
};

const ConvertMap* set_uid_map = &set_uid_api;

/**************************************************
 ********************* umask  *********************
 **************************************************/

static const std::string umask = "umask";
static const ConvertMap umask_api =
{
    umask,
    config_string_ctor<&umask, &process>,
};

const ConvertMap* umask_map = &umask_api;

} // namespace config
