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
// out_syslog.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>

#include "conversion_state.h"

namespace output
{
namespace
{
class AlertSyslog : public ConversionState
{
public:
    AlertSyslog(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool AlertSyslog::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_table("alert_syslog");
    std::streamoff pos = data_stream.tellg();

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword.back() == ',')
            keyword.pop_back();

        if (keyword.empty())
            continue;

        // snort is case insensitive.
        std::transform(keyword.begin(), keyword.end(), keyword.begin(), ::tolower);

        if (!keyword.compare(0, 5, "host="))
        {
            std::string hostname;
            data_stream.seekg(pos);
            data_stream >> hostname;    // output previously confirmed

            // FIXIT-L add when we start supporting windows
            table_api.add_comment("BINDINGS REQUIRED!! hostname --> --> " + hostname);
        }
        else if (keyword == "log_auth")
        {
            table_api.add_diff_option_comment("log_auth", "facility = auth");
            tmpval = table_api.add_option("facility", "auth");
        }
        else if (keyword == "log_authpriv")
        {
            table_api.add_diff_option_comment("log_authpriv", "facility = authpriv");
            tmpval = table_api.add_option("facility", "authpriv");
        }
        else if (keyword == "log_daemon")
        {
            table_api.add_diff_option_comment("log_daemon", "facility = daemon");
            tmpval = table_api.add_option("facility", "daemon");
        }
        else if (keyword == "log_user")
        {
            table_api.add_diff_option_comment("log_user", "facility = user");
            tmpval = table_api.add_option("facility", "user");
        }
        else if (keyword == "log_local0")
        {
            table_api.add_diff_option_comment("log_local0", "facility = local0");
            tmpval = table_api.add_option("facility", "local0");
        }
        else if (keyword == "log_local1")
        {
            table_api.add_diff_option_comment("log_local1", "facility = local1");
            tmpval = table_api.add_option("facility", "local1");
        }
        else if (keyword == "log_local2")
        {
            table_api.add_diff_option_comment("log_local2", "facility = local2");
            tmpval = table_api.add_option("facility", "local2");
        }
        else if (keyword == "log_local3")
        {
            table_api.add_diff_option_comment("log_local3", "facility = local3");
            tmpval = table_api.add_option("facility", "local3");
        }
        else if (keyword == "log_local4")
        {
            table_api.add_diff_option_comment("log_local4", "facility = local4");
            tmpval = table_api.add_option("facility", "local4");
        }
        else if (keyword == "log_local5")
        {
            table_api.add_diff_option_comment("log_local5", "facility = local5");
            tmpval = table_api.add_option("facility", "local5");
        }
        else if (keyword == "log_local6")
        {
            table_api.add_diff_option_comment("log_local6", "facility = local6");
            tmpval = table_api.add_option("facility", "local6");
        }
        else if (keyword == "log_local7")
        {
            table_api.add_diff_option_comment("log_local7", "facility = local7");
            tmpval = table_api.add_option("facility", "local7");
        }
        else if (keyword == "log_err")
        {
            table_api.add_diff_option_comment("log_err", "level = err");
            tmpval = table_api.add_option("level", "err");
        }
        else if (keyword == "log_emerg")
        {
            table_api.add_diff_option_comment("log_emerg", "level = emerg");
            tmpval = table_api.add_option("level", "emerg");
        }
        else if (keyword == "log_alert")
        {
            table_api.add_diff_option_comment("log_alert", "level = alert");
            tmpval = table_api.add_option("level", "alert");
        }
        else if (keyword == "log_crit")
        {
            table_api.add_diff_option_comment("log_crit", "level = crit");
            tmpval = table_api.add_option("level", "crit");
        }
        else if (keyword == "log_warning")
        {
            table_api.add_diff_option_comment("log_warning", "level = warning");
            tmpval = table_api.add_option("level", "warning");
        }
        else if (keyword == "log_notice")
        {
            table_api.add_diff_option_comment("log_notice", "level = notice");
            tmpval = table_api.add_option("level", "notice");
        }
        else if (keyword == "log_info")
        {
            table_api.add_diff_option_comment("log_info", "level = info");
            tmpval = table_api.add_option("level", "info");
        }
        else if (keyword == "log_debug")
        {
            table_api.add_diff_option_comment("log_debug", "level = debug");
            tmpval = table_api.add_option("level", "debug");
        }
        else if (keyword == "log_cons")
        {
            table_api.add_diff_option_comment("log_cons", "options = cons");
            tmpval = table_api.add_option("options", "cons");
        }
        else if (keyword == "log_ndelay")
        {
            table_api.add_diff_option_comment("log_ndelay", "options = ndelay");
            tmpval = table_api.add_option("options", "ndelay");
        }
        else if (keyword == "log_perror")
        {
            table_api.add_diff_option_comment("log_perror", "options = perror");
            tmpval = table_api.add_option("options", "perror");
        }
        else if (keyword == "log_pid")
        {
            table_api.add_diff_option_comment("log_pid", "options = pid");
            tmpval = table_api.add_option("options", "pid");
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

static ConversionState* ctor(Converter& c)
{
    c.get_table_api().open_top_level_table("alert_syslog"); // in case there are no arguments
    c.get_table_api().close_table();
    return new AlertSyslog(c);
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

