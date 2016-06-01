//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <sys/stat.h>

#include "perf_tracker.h"

#include "csv_formatter.h"
#include "perf_module.h"
#include "text_formatter.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "parser/parser.h"
#include "utils/util.h"

static inline bool check_file_size(FILE* fh, uint64_t max_file_size)
{
    int fd;
    struct stat file_stats;

    if (!fh)
        return false;

    fd = fileno(fh);
    if ((fstat(fd, &file_stats) == 0)
        && ((uint64_t)file_stats.st_size >= max_file_size))
        return true;

    return false;
}

PerfTracker::PerfTracker(PerfConfig* config, const char* tracker_fname)
{
    this->config = config;

    if (tracker_fname)
        get_instance_file(fname, tracker_fname);

    switch (config->format)
    {
        case PERF_CSV: formatter = new CSVFormatter(); break;
        case PERF_TEXT: formatter = new TextFormatter(); break;
#ifdef UNIT_TEST
        case PERF_MOCK: formatter = new MockFormatter(); break;
#endif
    }
}

PerfTracker::~PerfTracker()
{
    delete formatter;
    close();
}

void PerfTracker::open(bool append)
{
    if (fname.length())
    {
        // FIXIT-L this should be deleted; was added as 1-time workaround to
        // get around the borked perms due to a bug that has been fixed
        struct stat pt;
        mode_t mode =  S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
        const char* file_name = fname.c_str();

        /*Check file before change permission*/
        if (stat(file_name, &pt) == 0)
        {
            /*Only change permission for file owned by root*/
            if ((0 == pt.st_uid) || (0 == pt.st_gid))
            {
                if (chmod(file_name, mode) != 0)
                {
                    WarningMessage("perfmonitor: Unable to change mode of "
                        "stats file '%s' to mode:%u: %s.",
                        file_name, mode, get_error(errno));
                }

                if (chown(file_name, SnortConfig::get_uid(), SnortConfig::get_gid()) != 0)
                {
                    WarningMessage("perfmonitor: Unable to change permissions of "
                        "stats file '%s' to user:%d and group:%d: %s.",
                        file_name, SnortConfig::get_uid(), SnortConfig::get_gid(), get_error(
                        errno));
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
            ErrorMessage("perfmonitor: Cannot open stats file '%s'.", file_name);
    }
    else
        fh = stdout;

    formatter->init_output(fh);
}

void PerfTracker::close()
{
    if (fh && fh != stdout)
    {
        fclose(fh);
        fh = nullptr;
    }
}

// FIXIT-M combine with fileRotate
// FIXIT-M refactor file naming foo to use std::string
static bool rotate_file(const char* old_file, FILE* old_fh,
    uint32_t max_file_size)
{
    time_t ts;
    char rotate_file[PATH_MAX];
    struct stat file_stats;

    if (!old_file)
        return -1;

    if (!old_fh)
    {
        ErrorMessage("Perfmonitor: Performance stats file \"%s\" "
            "isn't open.\n", old_file);
        return -1;
    }

    // Close the current stats file if it's already open
    fclose(old_fh);
    old_fh = nullptr;

    // FIXIT-M does this make sense? or should it be the first timestamp in the file?
    // Rename current stats file with yesterday's date
    // Get current time, then subtract one day to get yesterday
    ts = time(nullptr);
    ts -= (24*60*60);

    // Create rotate file name based on path, optional prefix and date
    // Need to be mindful that we get 64-bit times on OSX
    SnortSnprintf(rotate_file, PATH_MAX, "%s_" STDu64,  old_file, (uint64_t)ts);

    // If the rotate file doesn't exist, just rename the old one to the new one
    if (stat(rotate_file, &file_stats) != 0)
    {
        if (rename(old_file, rotate_file) != 0)
        {
            ErrorMessage("Perfmonitor: Could not rename performance stats "
                "file from \"%s\" to \"%s\": %s.\n",
                old_file, rotate_file, get_error(errno));
        }
    }
    else  // Otherwise, if it does exist, append data from current stats file to it
    {
        char read_buf[4096];
        size_t num_read, num_wrote;
        FILE* rotate_fh;
        int rotate_index = 0;
        char rotate_file_with_index[PATH_MAX];

        // This file needs to be readable by everyone
        mode_t old_umask = umask(022);

        do
        {
            do
            {
                rotate_index++;

                // Check to see if there are any files already rotated and indexed
                SnortSnprintf(rotate_file_with_index, PATH_MAX, "%s.%02d",
                    rotate_file, rotate_index);
            }
            while (stat(rotate_file_with_index, &file_stats) == 0);

            // Subtract one to append to last existing file
            rotate_index--;

            if (rotate_index == 0)
            {
                rotate_file_with_index[0] = 0;
                rotate_fh = fopen(rotate_file, "a");
            }
            else
            {
                SnortSnprintf(rotate_file_with_index, PATH_MAX, "%s.%02d",
                    rotate_file, rotate_index);
                rotate_fh = fopen(rotate_file_with_index, "a");
            }

            if (!rotate_fh)
            {
                ErrorMessage("Perfmonitor: Could not open performance stats "
                    "archive file \"%s\" for appending: %s.\n",
                    *rotate_file_with_index ? rotate_file_with_index : rotate_file,
                    get_error(errno));
                break;
            }

            old_fh = fopen(old_file, "r");
            if (!old_fh)
            {
                ErrorMessage("Perfmonitor: Could not open performance stats file "
                    "\"%s\" for reading to copy to archive \"%s\": %s.\n",
                    old_file, (*rotate_file_with_index ? rotate_file_with_index :
                    rotate_file), get_error(errno));
                break;
            }

            while (!feof(old_fh))
            {
                // This includes the newline from the file.
                if (!fgets(read_buf, sizeof(read_buf), old_fh))
                {
                    if (feof(old_fh))
                        break;

                    if (ferror(old_fh))
                    {
                        // A read error occurred
                        ErrorMessage("Perfmonitor: Error reading performance stats "
                            "file \"%s\": %s.\n", old_file, get_error(errno));
                        break;
                    }
                }

                num_read = strlen(read_buf);

                if (num_read > 0)
                {
                    int rotate_fd = fileno(rotate_fh);

                    if (fstat(rotate_fd, &file_stats) != 0)
                    {
                        ErrorMessage("Perfmonitor: Error getting file "
                            "information for \"%s\": %s.\n",
                            *rotate_file_with_index ? rotate_file_with_index : rotate_file,
                            get_error(errno));
                        break;
                    }

                    if (((uint32_t)file_stats.st_size + num_read) > max_file_size)
                    {
                        fclose(rotate_fh);

                        rotate_index++;

                        // Create new file same as before but with an index added to the end
                        SnortSnprintf(rotate_file_with_index, PATH_MAX, "%s.%02d",
                            rotate_file, rotate_index);

                        rotate_fh = fopen(rotate_file_with_index, "a");
                        if (!rotate_fh)
                        {
                            ErrorMessage("Perfmonitor: Could not open performance "
                                "stats archive file \"%s\" for writing: %s.\n",
                                rotate_file_with_index, get_error(errno));
                            break;
                        }
                    }

                    num_wrote = fprintf(rotate_fh, "%s", read_buf);
                    if ((num_wrote != num_read) && ferror(rotate_fh))
                    {
                        // A bad write occurred
                        ErrorMessage("Perfmonitor: Error writing to performance "
                            "stats archive file \"%s\": %s.\n", rotate_file, get_error(errno));
                        break;
                    }

                    fflush(rotate_fh);
                }
            }
        }
        while (0);

        if (rotate_fh)
            fclose(rotate_fh);

        if (old_fh)
            fclose(old_fh);

        umask(old_umask);
    }

    return 0;
}

void PerfTracker::rotate()
{
    if (fh && fh != stdout)
    {
        bool ret = rotate_file(fname.c_str(), fh, config->max_file_size);
        if (ret != 0)
            return;
        open(false);
    }
}

void PerfTracker::auto_rotate()
{
    if (fh && fh != stdout && check_file_size(fh, config->max_file_size))
        rotate();
}

void PerfTracker::write()
{
    formatter->write(fh, cur_time);
}
