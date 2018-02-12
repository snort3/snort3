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
// output_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "output_states/output_api.h"

namespace output
{
extern const ConvertMap* alert_csv_map;
extern const ConvertMap* alert_fast_map;
extern const ConvertMap* alert_full_map;
extern const ConvertMap* alert_syslog_map;
extern const ConvertMap* alert_test_map;
extern const ConvertMap* alert_unified2_map;
extern const ConvertMap* log_null_map;
extern const ConvertMap* log_tcpdump_map;
extern const ConvertMap* log_unified2_map;
extern const ConvertMap* alert_unixsock_map;
extern const ConvertMap* unified2_map;
extern const ConvertMap* sfunified2_map;
extern const ConvertMap* sflog_unified2_map;
extern const ConvertMap* sfalert_unified2_map;

const std::vector<const ConvertMap*> output_api =
{
    alert_csv_map,
    alert_fast_map,
    alert_full_map,
    alert_syslog_map,
    alert_test_map,
    alert_unified2_map,
    log_null_map,
    log_tcpdump_map,
    log_unified2_map,
    alert_unixsock_map,
    unified2_map,
    sfunified2_map,
    sflog_unified2_map,
    sfalert_unified2_map
};
} // namespace output

