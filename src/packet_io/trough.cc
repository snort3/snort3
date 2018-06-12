//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <dirent.h>
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
std::string Trough::pcap_filter;
std::vector<std::string>::const_iterator Trough::pcap_queue_iter;
long Trough::pcap_loop_count = 0;
unsigned Trough::file_count = 0;

int Trough::get_pcaps(std::vector<struct PcapReadObject> &pol)
{
    for (const PcapReadObject &pro : pol)
    {
        const std::string& arg = pro.arg;
        const std::string& filter = pro.filter;

        switch (pro.type)
        {
            case SOURCE_FILE_LIST:
                /* arg should be a file with a list of pcaps in it */
                {
                    const char* whitespace = " \f\n\r\t\v";
                    std::ifstream pcap_list_file(arg);
                    std::string pcap_name;
                    struct stat sb;

                    if (!pcap_list_file.is_open())
                    {
                        ErrorMessage("Could not open pcap list file: %s: %s\n",
                                arg.c_str(), get_error(errno));
                        return -1;
                    }

                    while (getline(pcap_list_file, pcap_name))
                    {
                        /* Trim leading and trailing whitespace. */
                        pcap_name.erase(0, pcap_name.find_first_not_of(whitespace));
                        pcap_name.erase(pcap_name.find_last_not_of(whitespace) + 1);

                        if (pcap_name.empty())
                            continue;

                        /* do a quick check to make sure file exists */
                        if (snort::SnortConfig::read_mode() && stat(pcap_name.c_str(), &sb) == -1)
                        {
                            ErrorMessage("Error getting stat on pcap file: %s: %s\n",
                                    pcap_name.c_str(), get_error(errno));
                            pcap_list_file.close();
                            return -1;
                        }
                        else if (snort::SnortConfig::read_mode() && S_ISDIR(sb.st_mode))
                        {
                            Directory pcap_dir(pcap_name.c_str(), filter.c_str());
                            std::vector<std::string> tmp_queue;
                            const char* pcap_filename;

                            if (pcap_dir.error_on_open())
                            {
                                ErrorMessage("Error getting pcaps under dir: %s: %s\n",
                                        pcap_name.c_str(), get_error(pcap_dir.error_on_open()));
                                pcap_list_file.close();
                                return -1;
                            }
                            while ((pcap_filename = pcap_dir.next()))
                                tmp_queue.push_back(pcap_filename);
                            std::sort(tmp_queue.begin(), tmp_queue.end());
                            pcap_queue.reserve(pcap_queue.size() + tmp_queue.size());
                            pcap_queue.insert(pcap_queue.end(), tmp_queue.begin(), tmp_queue.end());
                        }
                        else if (!snort::SnortConfig::read_mode() || S_ISREG(sb.st_mode))
                        {
                            if (filter.empty() ||
                                (fnmatch(filter.c_str(), pcap_name.c_str(), 0) == 0))
                                pcap_queue.push_back(pcap_name);
                        }
                        else
                        {
                            ErrorMessage("Specified entry in \'%s\' is not a regular file or "
                                    "directory: %s\n", arg.c_str(), pcap_name.c_str());
                            pcap_list_file.close();
                            return -1;
                        }
                    }

                    pcap_list_file.close();
                }

                break;

            case SOURCE_LIST:
                /* arg should be a space separated list of pcaps */
                {
                    struct stat sb;
                    std::string pcap_name;
                    auto i = 0;
                    size_t pos = 0;

                    if (arg.empty())
                    {
                        ErrorMessage("No pcaps specified in pcap list\n");
                        return -1;
                    }

                    do
                    {
                        pos = arg.find(' ', i);
                        if (pos == std::string::npos)
                            pcap_name = arg.substr(i);
                        else
                        {
                            pcap_name = arg.substr(i, pos - i);
                            i = ++pos;
                        }
                        /* do a quick check to make sure file exists */
                        if (snort::SnortConfig::read_mode() and pcap_name != "-")
                        {
                            if (stat(pcap_name.c_str(), &sb) == -1)
                            {
                                ErrorMessage("Error getting stat on file: %s: %s (%d)\n",
                                        pcap_name.c_str(), get_error(errno), errno);
                                return -1;
                            }
                            if (!(sb.st_mode & (S_IFREG|S_IFIFO)))
                            {
                                ErrorMessage("Specified pcap is not a regular file: %s\n",
                                        pcap_name.c_str());
                                return -1;
                            }
                        }

                        pcap_queue.push_back(pcap_name);
                    } while (pos != std::string::npos);
                }

                break;

            case SOURCE_DIR:
                /* arg should be a directory name */
                {
                    Directory pcap_dir(arg.c_str(), filter.c_str());
                    std::vector<std::string> tmp_queue;
                    const char* pcap_filename;

                    if (pcap_dir.error_on_open())
                    {
                        ErrorMessage("Error getting pcaps under dir: %s: %s\n",
                                arg.c_str(), get_error(pcap_dir.error_on_open()));
                        return -1;
                    }
                    while ((pcap_filename = pcap_dir.next()))
                        tmp_queue.push_back(pcap_filename);
                    std::sort(tmp_queue.begin(), tmp_queue.end());
                    pcap_queue.reserve(pcap_queue.size() + tmp_queue.size());
                    pcap_queue.insert(pcap_queue.end(), tmp_queue.begin(), tmp_queue.end());
                }

                break;
        }
    }

    return 0;
}

void Trough::add_source(SourceType type, const char* list)
{
    PcapReadObject pro;

    pro.type = type;
    pro.arg = list;
    pro.filter = pcap_filter;

    pcap_object_list.push_back(pro);
}

void Trough::set_filter(const char *f)
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
        if (get_pcaps(pcap_object_list) == -1)
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

