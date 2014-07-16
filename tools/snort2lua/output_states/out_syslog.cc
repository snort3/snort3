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
// out_syslog.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/snort2lua_util.h"

namespace output
{

namespace
{

class AlertSyslog : public ConversionState
{
public:
    AlertSyslog( Converter* cv, LuaData* ld)
        :   ConversionState(cv, ld)
    { };
    virtual ~AlertSyslog() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool AlertSyslog::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    ld->open_table("alert_syslog");
    int pos = data_stream.tellg();

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword.back() == ',')
            keyword.pop_back();

        if (keyword.empty())
            continue;

        // snort is case insensitive.
        std::transform(keyword.begin(), keyword.end(), keyword.begin(), ::tolower);

        if(!keyword.compare(0, 5, "host="))
        {
            std::string hostname;
            data_stream.seekg(pos);
            data_stream >> hostname;    // output previously confirmed

            ld->add_comment_to_table("BINDINGS REQUIRED!! hostname --> --> " + hostname);
        }

        else if (!keyword.compare("log_auth"))
        {
            ld->add_diff_option_comment("log_auth", "facility = auth");
            tmpval = ld->add_option_to_table("facility", "auth");
        }

        else if (!keyword.compare("log_auth"))
        {
            ld->add_diff_option_comment("log_auth", "facility = auth");
            tmpval = ld->add_option_to_table("facility", "auth");
        }

        else if (!keyword.compare("log_authpriv"))
        {
            ld->add_diff_option_comment("log_authpriv", "facility = authpriv");
            tmpval = ld->add_option_to_table("facility", "authpriv");
        }

        else if (!keyword.compare("log_daemon"))
        {
            ld->add_diff_option_comment("log_daemon", "facility = daemon");
            tmpval = ld->add_option_to_table("facility", "daemon");
        }

        else if (!keyword.compare("log_user"))
        {
            ld->add_diff_option_comment("log_user", "facility = user");
            tmpval = ld->add_option_to_table("facility", "user");
        }

        else if (!keyword.compare("log_local0"))
        {
            ld->add_diff_option_comment("log_local0", "facility = local0");
            tmpval = ld->add_option_to_table("facility", "local0");
        }

        else if (!keyword.compare("log_local1"))
        {
            ld->add_diff_option_comment("log_local1", "facility = local1");
            tmpval = ld->add_option_to_table("facility", "local1");
        }

        else if (!keyword.compare("log_local2"))
        {
            ld->add_diff_option_comment("log_local2", "facility = local2");
            tmpval = ld->add_option_to_table("facility", "local2");
        }

        else if (!keyword.compare("log_local3"))
        {
            ld->add_diff_option_comment("log_local3", "facility = local3");
            tmpval = ld->add_option_to_table("facility", "local3");
        }

        else if (!keyword.compare("log_local4"))
        {
            ld->add_diff_option_comment("log_local4", "facility = local4");
            tmpval = ld->add_option_to_table("facility", "local4");
        }

        else if (!keyword.compare("log_local5"))
        {
            ld->add_diff_option_comment("log_local5", "facility = local5");
            tmpval = ld->add_option_to_table("facility", "local5");
        }

        else if (!keyword.compare("log_local6"))
        {
            ld->add_diff_option_comment("log_local6", "facility = local6");
            tmpval = ld->add_option_to_table("facility", "local6");
        }

        else if (!keyword.compare("log_local7"))
        {
            ld->add_diff_option_comment("log_local7", "facility = local7");
            tmpval = ld->add_option_to_table("facility", "local7");
        }

        else if (!keyword.compare("log_err"))
        {
            ld->add_diff_option_comment("log_err", "level = err");
            tmpval = ld->add_option_to_table("level", "err");
        }

        else if (!keyword.compare("log_emerg"))
        {
            ld->add_diff_option_comment("log_emerg", "level = emerg");
            tmpval = ld->add_option_to_table("level", "emerg");
        }

        else if (!keyword.compare("log_alert"))
        {
            ld->add_diff_option_comment("log_alert", "level = alert");
            tmpval = ld->add_option_to_table("level", "alert");
        }

        else if (!keyword.compare("log_crit"))
        {
            ld->add_diff_option_comment("log_crit", "level = crit");
            tmpval = ld->add_option_to_table("level", "crit");
        }

        else if (!keyword.compare("log_warning"))
        {
            ld->add_diff_option_comment("log_warning", "level = warning");
            tmpval = ld->add_option_to_table("level", "warning");
        }

        else if (!keyword.compare("log_notice"))
        {
            ld->add_diff_option_comment("log_notice", "level = notice");
            tmpval = ld->add_option_to_table("level", "notice");
        }

        else if (!keyword.compare("log_info"))
        {
            ld->add_diff_option_comment("log_info", "level = info");
            tmpval = ld->add_option_to_table("level", "info");
        }

        else if (!keyword.compare("log_debug"))
        {
            ld->add_diff_option_comment("log_debug", "level = debug");
            tmpval = ld->add_option_to_table("level", "debug");
        }

        else if (!keyword.compare("log_cons"))
        {
            ld->add_diff_option_comment("log_cons", "options = cons");
            tmpval = ld->add_option_to_table("options", "cons");
        }

        else if (!keyword.compare("log_ndelay"))
        {
            ld->add_diff_option_comment("log_ndelay", "options = ndelay");
            tmpval = ld->add_option_to_table("options", "ndelay");
        }

        else if (!keyword.compare("log_perror"))
        {
            ld->add_diff_option_comment("log_perror", "options = perror");
            tmpval = ld->add_option_to_table("options", "perror");
        }

        else if (!keyword.compare("log_pid"))
        {
            ld->add_diff_option_comment("log_pid", "options = pid");
            tmpval = ld->add_option_to_table("options", "pid");
        }

        else
        {
            tmpval = false;
        }

        if (retval)
            retval = tmpval;

        // for the possibly case sensitive host name
        pos = data_stream.tellg();
    }

    return retval;
}


static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    ld->open_top_level_table("alert_syslog"); // in case there are no arguments
    ld->close_table();
    return new AlertSyslog(cv, ld);
}



/**************************
 *******  A P I ***********
 **************************/


static const ConvertMap syslog_api =
{
    "alert_syslog",
    ctor,
};

const ConvertMap* alert_syslog_map = &syslog_api;

} // output namespace

