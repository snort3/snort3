//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// perf_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "perf_tracker.h"

#include <sys/stat.h>

#include <climits>

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "csv_formatter.h"
#include "json_formatter.h"
#include "text_formatter.h"

using namespace snort;
using namespace std;

PerfTracker::PerfTracker(PerfConfig* config, const char* tracker_name)
{
    max_file_size = config->max_file_size;

    switch (config->format)
    {
        case PerfFormat::CSV: formatter = new CSVFormatter(tracker_name); break;
        case PerfFormat::TEXT: formatter = new TextFormatter(tracker_name); break;
        case PerfFormat::JSON: formatter = new JSONFormatter(tracker_name); break;
#ifdef UNIT_TEST
        case PerfFormat::MOCK: formatter = new MockFormatter(tracker_name); break;
#endif
        default:
            FatalError("Perfmonitor: Can't initialize output format\n");
            break;
    }

    if ( config->output == PerfOutput::TO_FILE )
    {
        string tracker_fname = tracker_name;
        tracker_fname += formatter->get_extension();
        get_instance_file(fname, tracker_fname.c_str());
    }

    this->tracker_name = tracker_name;
}

PerfTracker::~PerfTracker()
{
    close();

    delete formatter;
}

void PerfTracker::close()
{
    if (fh)
    {
        formatter->finalize_output(fh);
        if (fh != stdout)
        {
            fclose(fh);
            fh = nullptr;
        }
    }
}

bool PerfTracker::open(bool append)
{
    if (fname.length())
    {
        // FIXIT-L this should be deleted; was added as 1-time workaround to
        // get around the borked perms due to a bug that has been fixed
        struct stat pt;
        mode_t mode =  S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
        const char* file_name = fname.c_str();
        bool existed = false;

        // Check file before change permission
        if (stat(file_name, &pt) == 0)
        {
            existed = true;

            // Only change permission for file owned by root
            if ((0 == pt.st_uid) || (0 == pt.st_gid))
            {
                if (chmod(file_name, mode) != 0)
                {
                    WarningMessage("perfmonitor: Unable to change mode of "
                        "stats file '%s' to mode:%u: %s.\n",
                        file_name, mode, get_error(errno));
                }

                const SnortConfig* sc = SnortConfig::get_conf();

                if (chown(file_name, sc->get_uid(), sc->get_gid()) != 0)
                {
                    WarningMessage("perfmonitor: Unable to change permissions of "
                        "stats file '%s' to user:%d and group:%d: %s.\n",
                        file_name, sc->get_uid(), sc->get_gid(), get_error(errno));
                }
            }
        }

        // This file needs to be readable by everyone
        mode_t old_umask = umask(022);
        // Append to the existing file if just starting up, otherwise we've
        // rotated so start a new one.
        fh = fopen(file_name, append ? "a" : "w");
        umask(old_umask);

        if (!fh)
        {
            ErrorMessage("perfmonitor: Cannot open stats file '%s'.\n", file_name);
            return false;
        }

        // FIXIT-L refactor rotation so it doesn't require an open file handle
        if (existed && append && !formatter->allow_append())
            return rotate();
    }
    else
        fh = stdout;

    formatter->init_output(fh);

    return true;
}

bool PerfTracker::rotate()
{
    if (fh && fh != stdout)
    {
        if (!rotate_file_for_max_size("Perfmonitor", fname.c_str(), fh, max_file_size))
            return false;

        return open(false);
    }
    return true;
}

bool PerfTracker::auto_rotate()
{
    if (fh && fh != stdout && check_file_size(fh, max_file_size))
        return rotate();

    return true;
}

void PerfTracker::write()
{
    formatter->write(fh, cur_time);
}
