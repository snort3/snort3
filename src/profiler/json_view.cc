//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
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

// json_view.cc author Anna Norokh <anorokh@cisco.com>

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "json_view.h"

#include <sstream>
#include <vector>

#include "control/control.h"
#include "helpers/json_stream.h"
#include "main/snort_config.h"

#include "profiler_printer.h"
#include "rule_profiler.h"

#define PRECISION 5

using namespace snort;

static void print_single_entry(ControlConn* ctrlcon, const rule_stats::View& v, unsigned n,
    unsigned count, double total_time_usec)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    std::ostringstream ss;
    JsonStream json(ss);

    json.open();
    json.put("gid", v.sig_info.gid);
    json.put("sid", v.sig_info.sid);
    json.put("rev", v.sig_info.rev);

    json.put("checks", v.checks());
    json.put("matches", v.matches());
    json.put("alerts", v.alerts());

    json.put("timeUs", clock_usecs(TO_USECS(v.elapsed())));
    json.put("avgCheck", clock_usecs(TO_USECS(v.avg_check())));
    json.put("avgMatch", clock_usecs(TO_USECS(v.avg_match())));
    json.put("avgNonMatch", clock_usecs(TO_USECS(v.avg_no_match())));

    json.put("timeouts", v.timeouts());
    json.put("suspends", v.suspends());
    json.put("ruleTimePercentage", v.rule_time_per(total_time_usec), PRECISION);
    json.close();


    if ( n < count )
        ss << ", ";

    LogRespond(ctrlcon, "%s", ss.str().c_str());
}

void print_json_entries(ControlConn* ctrlcon, std::vector<rule_stats::View>& entries,
    ProfilerSorter<rule_stats::View>& sort, unsigned count)
{
    std::ostringstream ss;
    JsonStream json(ss);

    RuleContext::count_total_time();

    json.open();
    json.put("startTime", RuleContext::get_start_time()->tv_sec);
    json.put("endTime", RuleContext::get_end_time()->tv_sec);
    json.open_array("rules");
    json.put_eol();

    LogRespond(ctrlcon, "%s", ss.str().c_str());

    if ( !count || count > entries.size() )
        count = entries.size();

    if ( sort )
        std::partial_sort(entries.begin(), entries.begin() + count, entries.end(), sort);

    double total_time_usec =
        RuleContext::get_total_time()->tv_sec * 1000000.0 + RuleContext::get_total_time()->tv_usec;

    for ( unsigned i = 0; i < count; ++i )
        print_single_entry(ctrlcon, entries[i], i + 1, count, total_time_usec);

    //clean the stream from previous data
    ss.str("");
    json.close_array();
    json.close();

    LogRespond(ctrlcon, "%s", ss.str().c_str());
}
