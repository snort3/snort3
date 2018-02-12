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

#ifndef TROUGH_H
#define TROUGH_H

#include <string>
#include <vector>

// Trough provides access to sources (interface, file, etc.).

class Trough
{
public:
    enum SourceType
    {
        SOURCE_FILE_LIST,  // a file containing a list of sources
        SOURCE_LIST,       // a list of sources (eg from cmd line)
        SOURCE_DIR         // a directory of sources; often used with filter
    };

    static void set_loop_count(long int c)
    {
        pcap_loop_count = c;
    }
    static void set_filter(const char *f);
    static void add_source(SourceType type, const char *list);
    static void setup();
    static bool has_next();
    static const char *get_next();
    static unsigned get_file_count()
    {
        return file_count;
    }
    static unsigned get_queue_size()
    {
        return pcap_queue.size();
    }
    static long get_loop_count()
    {
        return pcap_loop_count;
    }
    static void cleanup();
private:
    struct PcapReadObject
    {
        SourceType type;
        std::string arg;
        std::string filter;
    };

    static int get_pcaps(std::vector<struct PcapReadObject> &pol);
    static std::vector<struct PcapReadObject> pcap_object_list;
    static std::vector<std::string> pcap_queue;
    static std::vector<std::string>::const_iterator pcap_queue_iter;
    static std::string pcap_filter;
    static long pcap_loop_count;
    static unsigned file_count;
};

#endif

