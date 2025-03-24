//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util.h"

#include <sys/resource.h>
#include <sys/stat.h>

#include <chrono>
#include <random>

#include "log/messages.h"
#include "main/snort_config.h"

#include "util_cstring.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#ifdef _WIN32
#define STAT _stat
#else
#define STAT stat
#endif

#ifdef _WIN32
#define ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#define ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#else
#define ISREG(m) S_ISREG(m)
#define ISDIR(m) S_ISDIR(m)
#endif

using namespace snort;

unsigned int get_random_seed()
{
    unsigned int seed;

    try {
        seed = std::random_device{}();
    } catch ( const std::exception& ) {
        seed = std::chrono::system_clock::now().time_since_epoch().count();
    }

    return seed;
}

bool get_file_size(const std::string& path, size_t& size)
{
    struct STAT sb;

    if (STAT(path.c_str(), &sb))
        return false;

    if (!ISREG(sb.st_mode))
        return false;

    if (sb.st_size < 0)
        return false;

    size = static_cast<size_t>(sb.st_size);
    return true;
}

namespace snort
{
bool is_directory_path(const std::string& path)
{
    struct STAT sb;

    if (STAT(path.c_str(), &sb))
        return false;

    return ISDIR(sb.st_mode);
}

const char* get_error(int errnum)
{
    static THREAD_LOCAL char buf[128];

#if defined(HAVE_GNU_STRERROR_R)
    return strerror_r(errnum, buf, sizeof(buf));
#else
    (void)strerror_r(errnum, buf, sizeof(buf));
    return buf;
#endif
}

char* snort_strndup(const char* src, size_t n)
{
    char* dst = (char*)snort_calloc(n + 1);
    return strncpy(dst, src, n);
}

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}

void ts_print(const struct timeval* tvp, char* timebuf, bool yyyymmdd)
{
    struct timeval tv;
    struct timezone tz;

    // if null was passed, use current time
    if (!tvp)
    {
        // manual page (for linux) says tz is never used, so..
        memset((char*)&tz, 0, sizeof(tz));
        gettimeofday(&tv, &tz);
        tvp = &tv;
    }

    const SnortConfig* sc = SnortConfig::get_conf();
    int localzone = sc->thiszone;

    // If we're doing UTC, then make sure that the timezone is correct.
    if (sc->output_use_utc())
        localzone = 0;

    int s = (tvp->tv_sec + localzone) % SECONDS_PER_DAY;
    time_t Time = (tvp->tv_sec + localzone) - s;

    struct tm ttm;
    struct tm* lt = gmtime_r(&Time, &ttm);

    if ( !lt )
    {
        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE, "%lu", tvp->tv_sec);

    }
    else if (sc->output_include_year())
    {
        int year = (lt->tm_year >= 100) ? (lt->tm_year - 100) : lt->tm_year;

        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
            year, lt->tm_mon + 1, lt->tm_mday,
            s / 3600, (s % 3600) / 60, s % 60,
            (unsigned)tvp->tv_usec);
    }
    else if (yyyymmdd)
    {
        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%04d-%02d-%02d %02d:%02d:%02d.%06u",
            lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
            s / 3600, (s % 3600) / 60, s % 60,
            (unsigned)tvp->tv_usec);
    }
    else
    {
        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%02d/%02d-%02d:%02d:%02d.%06u", lt->tm_mon + 1,
            lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
            (unsigned)tvp->tv_usec);
    }
}

static void start_hex_state(bool& hex_state, std::string& print_str)
{
    if (!hex_state)
    {
        hex_state = true;
        print_str += "|";
    }
}

static void end_hex_state(bool& hex_state, std::string& print_str)
{
    if (hex_state)
    {
        hex_state = false;
        print_str += "|";
    }
}

void uint8_to_printable_str(const uint8_t* buff, unsigned len, std::string& print_str)
{
    print_str.clear();
    char output[4];
    bool hex_state = false;
    for (unsigned i = 0 ; i < len ; i++)
    {
        if ((buff[i] >= 0x20) && (buff[i] <= 0x7E))
        {
            end_hex_state(hex_state, print_str);
            sprintf(output, "%c", (char)buff[i]);
        }
        else
        {
            start_hex_state(hex_state, print_str);
            sprintf(output, "%.2x ", buff[i]);
        }

        print_str += output;
    }

    end_hex_state(hex_state, print_str);
}

void str_to_int_vector(const std::string& s, char delim, std::vector<uint32_t>& elems)
{
    std::istringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        size_t pos;
        uint32_t i = std::stoul(item, &pos);
        elems.push_back(i);
    }
}

std::string int_vector_to_str(const std::vector<uint32_t>& elems, char delim)
{
    std::string str = "none";
    if (elems.size())
    {
        std::ostringstream oss;
        for (size_t i = 0; i < elems.size(); ++i)
        {
            oss << elems[i];
            if (i < elems.size() - 1)
                oss << delim;
        }
        str = oss.str();
    }

    return str;
}

bool check_file_size(FILE* fh, uint64_t max_file_size)
{
    int fd;
    struct stat fstats;

    if (!fh)
        return false;

    fd = fileno(fh);
    if ((fstat(fd, &fstats) == 0)
        && ((uint64_t)fstats.st_size >= max_file_size))
        return true;

    return false;
}

bool rotate_file_for_max_size(const char* file_owner, const char* old_file,
    FILE* old_fh, uint32_t max_file_size)
{
    time_t ts;
    char rotate_file[PATH_MAX];
    struct stat fstats;

    if (!old_file)
        return false;

    if (!old_fh)
    {
        ErrorMessage("%s: file \"%s\" isn't open.\n", file_owner, old_file);
        return false;
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
    if (stat(rotate_file, &fstats) != 0)
    {
        if (rename(old_file, rotate_file) != 0)
        {
            ErrorMessage("%s: Could not rename "
                "file from \"%s\" to \"%s\": %s.\n",
                file_owner, old_file, rotate_file, get_error(errno));
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
            while (stat(rotate_file_with_index, &fstats) == 0);

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
                ErrorMessage("%s: Could not open "
                    "archive file \"%s\" for appending: %s.\n",
                    file_owner, *rotate_file_with_index ? rotate_file_with_index : rotate_file,
                    get_error(errno));
                break;
            }

            old_fh = fopen(old_file, "r");
            if (!old_fh)
            {
                ErrorMessage("%s: Could not open file "
                    "\"%s\" for reading to copy to archive \"%s\": %s.\n",
                    file_owner, old_file, (*rotate_file_with_index ? rotate_file_with_index :
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
                        ErrorMessage("%s: Error reading "
                            "file \"%s\": %s.\n", file_owner, old_file, get_error(errno));
                        break;
                    }
                }

                num_read = strlen(read_buf);

                if (num_read > 0)
                {
                    int rotate_fd = fileno(rotate_fh);

                    if (fstat(rotate_fd, &fstats) != 0)
                    {
                        ErrorMessage("%s: Error getting file "
                            "information for \"%s\": %s.\n",
                            file_owner, *rotate_file_with_index ? rotate_file_with_index : rotate_file,
                            get_error(errno));
                        break;
                    }

                    if (((uint32_t)fstats.st_size + num_read) > max_file_size)
                    {
                        fclose(rotate_fh);

                        rotate_index++;

                        // Create new file same as before but with an index added to the end
                        SnortSnprintf(rotate_file_with_index, PATH_MAX, "%s.%02d",
                            rotate_file, rotate_index);

                        rotate_fh = fopen(rotate_file_with_index, "a");
                        if (!rotate_fh)
                        {
                            ErrorMessage("%s: Could not open "
                                "stats archive file \"%s\" for writing: %s.\n",
                                file_owner, rotate_file_with_index, get_error(errno));
                            break;
                        }
                    }

                    num_wrote = fprintf(rotate_fh, "%s", read_buf);
                    if ((num_wrote != num_read) && ferror(rotate_fh))
                    {
                        // A bad write occurred
                        ErrorMessage("%s: Error writing to "
                            "stats archive file \"%s\": %s.\n", file_owner, rotate_file, get_error(errno));
                        break;
                    }

                    fflush(rotate_fh);
                }
            }
        }
        while (false);

        if (rotate_fh)
            fclose(rotate_fh);

        if (old_fh)
            fclose(old_fh);

        umask(old_umask);
    }

    return true;
}

}

#ifdef UNIT_TEST
TEST_CASE("uint8_to_printable_str go over all options", "[util]")
{
    std::string print_str;
    uint8_t pattern[] = { 0, 'a', '(', 'd', ')', 1, '\r', 2, '\n','n'};
    uint8_to_printable_str(pattern, 10, print_str);
    CHECK((strcmp(print_str.c_str(),"|00 |a(d)|01 0d 02 0a |n") == 0));
}

TEST_CASE("uint8_to_printable_str empty buffer", "[util]")
{
    std::string print_str;
    uint8_t* pattern = nullptr;
    uint8_to_printable_str(pattern, 0, print_str);
    CHECK((strcmp(print_str.c_str(),"") == 0));
}

TEST_CASE("uint8_to_printable_str end with |", "[util]")
{
    std::string print_str;
    uint8_t pattern[] = { 'a', 0 };
    uint8_to_printable_str(pattern, 2, print_str);
    CHECK((strcmp(print_str.c_str(),"a|00 |") == 0));
}
#endif

