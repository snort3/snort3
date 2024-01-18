//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// table_view.cc author Joel Cornett <jocornet@cisco.com>

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "table_view.h"

#include <sstream>
#include <vector>

#include "control/control.h"
#include "detection/treenodes.h"

#include "profiler_printer.h"
#include "profiler_stats_table.h"
#include "rule_profiler.h"

#define s_rule_table_title "rule profile"

using namespace snort;

const StatsTable::Field fields[] =
{
    { "#", 5, '\0', 0, std::ios_base::left },
    { "gid", 6, '\0', 0, std::ios_base::fmtflags() },
    { "sid", 6, '\0', 0, std::ios_base::fmtflags() },
    { "rev", 4, '\0', 0, std::ios_base::fmtflags() },
    { "checks", 10, '\0', 0, std::ios_base::fmtflags() },
    { "matches", 8, '\0', 0, std::ios_base::fmtflags() },
    { "alerts", 7, '\0', 0, std::ios_base::fmtflags() },
    { "time (us)", 10, '\0', 0, std::ios_base::fmtflags() },
    { "avg/check", 10, '\0', 1, std::ios_base::fmtflags() },
    { "avg/match", 10, '\0', 1, std::ios_base::fmtflags() },
    { "avg/non-match", 14, '\0', 1, std::ios_base::fmtflags() },
    { "timeouts", 9, '\0', 0, std::ios_base::fmtflags() },
    { "suspends", 9, '\0', 0, std::ios_base::fmtflags() },
    { "rule_time (%)", 14, '\0', 5, std::ios_base::fmtflags() },
    { nullptr, 0, '\0', 0, std::ios_base::fmtflags() }
};

// FIXIT-L logic duplicated from ProfilerPrinter
static void print_single_entry(ControlConn* ctrlcon, const rule_stats::View& v, unsigned n,
    double total_time_usec)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    std::ostringstream ss;

    {
        StatsTable table(fields, ss);

        table << StatsTable::ROW;

        table << n; // #

        table << v.sig_info.gid;
        table << v.sig_info.sid;
        table << v.sig_info.rev;

        table << v.checks();
        table << v.matches();
        table << v.alerts();

        table << clock_usecs(TO_USECS(v.elapsed()));
        table << clock_usecs(TO_USECS(v.avg_check()));
        table << clock_usecs(TO_USECS(v.avg_match()));
        table << clock_usecs(TO_USECS(v.avg_no_match()));

        table << v.timeouts();
        table << v.suspends();
        table << v.rule_time_per(total_time_usec);
    }

    LogRespond(ctrlcon, "%s", ss.str().c_str());
}

// FIXIT-L logic duplicated from ProfilerPrinter
void print_entries(ControlConn* ctrlcon, std::vector<rule_stats::View>& entries,
    ProfilerSorter<rule_stats::View>& sort, unsigned count)
{
    std::ostringstream ss;
    RuleContext::count_total_time();

    double total_time_usec =
        ( RuleContext::get_total_time()->tv_sec * 1000000.0 + RuleContext::get_total_time()->tv_usec )
        * ThreadConfig::get_instance_max();

    StatsTable table(fields, ss);

    table << StatsTable::SEP;

    table << s_rule_table_title;
    if ( count )
        table << " (worst " << count;
    else
        table << " (all";

    if ( sort )
        table << ", sorted by " << sort.name;

    table << ")\n";

    table << StatsTable::HEADER;

    LogRespond(ctrlcon, "%s", ss.str().c_str());

    if ( !count || count > entries.size() )
        count = entries.size();

    if ( sort )
        std::partial_sort(entries.begin(), entries.begin() + count, entries.end(), sort);

    for ( unsigned i = 0; i < count; ++i )
        print_single_entry(ctrlcon, entries[i], i + 1, total_time_usec);

}
