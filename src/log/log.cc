//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#include "log.h"

#include <netdb.h>
#include <mutex>

#include "main/thread.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "batched_logger.h"
#include "log_text.h"
#include "messages.h"

using namespace snort;

#define DEFAULT_DAEMON_ALERT_FILE  "alert"

/****************************************************************************
 *
 * Function: OpenAlertFile(char *)
 *
 * Purpose: Set up the file pointer/file for alerting
 *
 * Arguments: filearg => the filename to open
 *
 * Returns: file handle
 *
 ***************************************************************************/
FILE* OpenAlertFile(const char* filearg, bool is_critical)
{
    FILE* file;

    if ( !filearg )
        filearg = "alert.txt";

    std::string name;
    const char* filename = get_instance_file(name, filearg);

    if ((file = fopen(filename, "a")) == nullptr)
    {
        if (is_critical)
            FatalError("OpenAlertFile() => fopen() alert file %s: %s\n", filename, get_error(errno));
        else
            ErrorMessage("OpenAlertFile() => fopen() alert file %s: %s\n", filename, get_error(errno));
    }
    else
        setvbuf(file, (char*)nullptr, _IOLBF, (size_t)0);

    return file;
}

/****************************************************************************
 *
 * Function: RollAlertFile(char *)
 *
 * Purpose: rename existing alert file with by appending time to name
 *
 * Arguments: filearg => the filename to rename (same as for OpenAlertFile())
 *
 * Returns: 0=success, else errno
 *
 ***************************************************************************/
int RollAlertFile(const char* filearg)
{
    char newname[STD_BUF+1];
    time_t now = time(nullptr);

    if ( !filearg )
        filearg = "alert.txt";

    std::string name;
    get_instance_file(name, filearg);
    const char* oldname = name.c_str();

    SnortSnprintf(newname, sizeof(newname)-1, "%s.%lu", oldname, (unsigned long)now);


    if ( rename(oldname, newname) )
    {
        FatalError("RollAlertFile() => rename(%s, %s) = %s\n",
            oldname, newname, get_error(errno));
    }
    return errno;
}

//--------------------------------------------------------------------
// default logger stuff
//--------------------------------------------------------------------

static std::mutex log_mutex;

static TextLog* text_log = nullptr;

void OpenLogger()
{
    text_log = TextLog_Init("stdout", 300*1024);
}

void CloseLogger()
{
    BatchedLogger::BatchedLogManager::shutdown();
    TextLog_Term(text_log);
}

void LogIPPkt(Packet* p)
{
    log_mutex.lock();
    TextLog_NewLine(text_log);
    LogTimeStamp(text_log, p);
    LogIPPkt(text_log, p);
    TextLog_Flush(text_log);
    log_mutex.unlock();
}

void LogFlow(Packet* p)
{
    log_mutex.lock();
    TextLog_NewLine(text_log);
    LogTimeStamp(text_log, p);
    TextLog_Print(text_log, " %s ", p->get_type());
    LogIpAddrs(text_log, p);
    TextLog_NewLine(text_log);
    log_mutex.unlock();
}

void LogNetData(const uint8_t* data, const int len, Packet* p)
{
    log_mutex.lock();
    LogNetData(text_log, data, len, p);
    TextLog_Flush(text_log);
    log_mutex.unlock();
}

//--------------------------------------------------------------------
// protocol translation
//--------------------------------------------------------------------

static char** protocol_names = nullptr;

const char* get_protocol_name(uint8_t ip_proto)
{
    assert(protocol_names and protocol_names[ip_proto]);
    return protocol_names[ip_proto];
}

void InitProtoNames()
{
    if ( !protocol_names )
        protocol_names = (char**)snort_calloc(NUM_IP_PROTOS, sizeof(char*));

    for ( int i = 0; i < NUM_IP_PROTOS; i++ )
    {
        struct protoent* pt = getprotobynumber(i);  // main thread only

        if (pt != nullptr)
        {
            protocol_names[i] = snort_strdup(pt->p_name);

            for ( size_t j = 0; j < strlen(protocol_names[i]); j++ )
                protocol_names[i][j] = toupper(protocol_names[i][j]);
        }
        else
        {
            char protoname[10];
            SnortSnprintf(protoname, sizeof(protoname), "PROTO:%03d", i);
            protocol_names[i] = snort_strdup(protoname);
        }
    }
}

void CleanupProtoNames()
{
    if (protocol_names != nullptr)
    {
        int i;

        for (i = 0; i < NUM_IP_PROTOS; i++)
        {
            if (protocol_names[i] != nullptr)
                snort_free(protocol_names[i]);
        }

        snort_free(protocol_names);
        protocol_names = nullptr;
    }
}

