//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "trough.h"

#include <fnmatch.h>
#include <sys/stat.h>

#include <algorithm>
#include <fstream>

#include "helpers/directory.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "utils/util.h"

using namespace snort;

std::vector<struct Trough::PcapReadObject> Trough::pcap_object_list;
std::vector<std::string> Trough::pcap_queue;
std::string Trough::pcap_filter = "*.*cap*";
std::vector<std::string>::const_iterator Trough::pcap_queue_iter;

unsigned Trough::pcap_loop_count = 0;
std::atomic<unsigned> Trough::file_count{0};

bool Trough::add_pcaps_dir(const std::string& dirname, const std::string& filter)
{
    Directory pcap_dir(dirname.c_str(), filter.c_str());
    if (pcap_dir.error_on_open())
    {
        ErrorMessage("Error getting pcaps under dir: %s: %s\n",
                dirname.c_str(), get_error(pcap_dir.error_on_open()));
        return false;
    }

    std::vector<std::string> tmp_queue;
    const char* pcap_filename;
    while ((pcap_filename = pcap_dir.next()))
        tmp_queue.emplace_back(pcap_filename);
    std::sort(tmp_queue.begin(), tmp_queue.end());

    pcap_queue.reserve(pcap_queue.size() + tmp_queue.size());
    pcap_queue.insert(pcap_queue.end(), tmp_queue.begin(), tmp_queue.end());

    return true;
}

bool Trough::add_pcaps_list_file(const std::string& list_filename, const std::string& filter)
{
    std::ifstream pcap_list_file(list_filename);
    if (!pcap_list_file.is_open())
    {
        ErrorMessage("Could not open pcap list file: %s: %s\n", list_filename.c_str(), get_error(errno));
        return false;
    }

    std::string pcap_name;
    while (getline(pcap_list_file, pcap_name))
    {
        /* Trim leading and trailing whitespace. */
        constexpr const char* whitespace = " \f\n\r\t\v";
        pcap_name.erase(0, pcap_name.find_first_not_of(whitespace));
        pcap_name.erase(pcap_name.find_last_not_of(whitespace) + 1);

        if (pcap_name.empty())
            continue;

        /* do a quick check to make sure file exists */
        struct stat sb;
        if (stat(pcap_name.c_str(), &sb) == -1)
        {
            ErrorMessage("Error getting stat on pcap file: %s: %s\n", pcap_name.c_str(), get_error(errno));
            pcap_list_file.close();
            return false;
        }
        if (S_ISDIR(sb.st_mode))
        {
            if (!add_pcaps_dir(pcap_name, filter))
            {
                pcap_list_file.close();
                return false;
            }
        }
        else if (S_ISREG(sb.st_mode))
        {
            if (filter.empty() || (fnmatch(filter.c_str(), pcap_name.c_str(), 0) == 0))
                pcap_queue.emplace_back(pcap_name);
        }
        else
        {
            ErrorMessage("Specified entry in \'%s\' is not a regular file or directory: %s\n",
                    list_filename.c_str(), pcap_name.c_str());
            pcap_list_file.close();
            return false;
        }
    }
    pcap_list_file.close();

    return true;
}

bool Trough::add_pcaps_list(const std::string& list)
{
    if (list.empty())
    {
        ErrorMessage("No pcaps specified in pcap list\n");
        return false;
    }

    std::string pcap_name;
    size_t i = 0;
    size_t pos = 0;

    do
    {
        pos = list.find(' ', i);
        if (pos == std::string::npos)
            pcap_name = list.substr(i);
        else
        {
            pcap_name = list.substr(i, pos - i);
            i = ++pos;
        }
        /* do a quick check to make sure file exists */
        if (pcap_name != "-")
        {
            struct stat sb;
            if (stat(pcap_name.c_str(), &sb) == -1)
            {
                ErrorMessage("Error getting stat on file: %s: %s (%d)\n",
                        pcap_name.c_str(), get_error(errno), errno);
                return false;
            }
            if (!(sb.st_mode & (S_IFREG|S_IFIFO)))
            {
                ErrorMessage("Specified pcap is not a regular file: %s\n", pcap_name.c_str());
                return false;
            }
        }

        pcap_queue.emplace_back(pcap_name);
    } while (pos != std::string::npos);

    return true;
}

bool Trough::get_pcaps(const std::vector<struct PcapReadObject> &pol)
{
    for (const PcapReadObject &pro : pol)
    {
        switch (pro.type)
        {
            case SOURCE_FILE_LIST:
                /* arg should be a file with a list of pcaps in it */
                if (!add_pcaps_list_file(pro.arg, pro.filter))
                    return false;
                break;

            case SOURCE_LIST:
                /* arg should be a space separated list of pcaps */
                if (!add_pcaps_list(pro.arg))
                    return false;
                break;

            case SOURCE_DIR:
                /* arg should be a directory name */
                if (!add_pcaps_dir(pro.arg, pro.filter))
                    return false;
                break;
        }
    }

    return true;
}

void Trough::add_source(SourceType type, const char* list)
{
    PcapReadObject pro;

    pro.type = type;
    pro.arg = list;
    pro.filter = pcap_filter;

    pcap_object_list.emplace_back(pro);
}

void Trough::set_filter(const char* f)
{
    if (f)
        pcap_filter = f;
    else
        pcap_filter.erase();
}

void Trough::setup()
{
    if (!pcap_object_list.empty())
    {
        if (!get_pcaps(pcap_object_list))
            FatalError("Error getting pcaps.\n");

        if (pcap_queue.empty())
            FatalError("No pcaps found.\n");

        /* free pcap list used to get params */
        pcap_object_list.clear();

        pcap_queue_iter = pcap_queue.cbegin();
    }
    pcap_filter.clear();
}

void Trough::cleanup()
{
    /* clean up pcap queues */
    pcap_queue.clear();
}

const char* Trough::get_next()
{
    const char* pcap = nullptr;

    if (pcap_queue.empty() || pcap_queue_iter == pcap_queue.cend())
        return nullptr;

    pcap = pcap_queue_iter->c_str();
    ++pcap_queue_iter;
    /* If we've reached the end, reset the iterator if we have more
        loops to cover. */
    if (pcap_queue_iter == pcap_queue.cend() && pcap_loop_count > 1)
    {
        pcap_loop_count--;
        pcap_queue_iter = pcap_queue.cbegin();
    }

    file_count++;
    return pcap;
}

bool Trough::has_next()
{
    return (!pcap_queue.empty() && pcap_queue_iter != pcap_queue.cend());
}

