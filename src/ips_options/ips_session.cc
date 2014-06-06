/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* Snort Session Logging Plugin */

/* sp_session
 *
 * Purpose:
 *
 * Drops data (printable or otherwise) into a SESSION file.  Useful for
 * logging user sessions (telnet, http, ftp, etc).
 *
 * Arguments:
 *
 * This plugin can take two arguments:
 *    printable => only log the "printable" ASCII characters.
 *    all       => log all traffic in the session, logging non-printable
 *                 chars in "\xNN" hexidecimal format
 *
 * Effect:
 *
 * Warning, this plugin may slow Snort *way* down!
 *
 */
// FIXIT delete this (sp_session) and use session tag instead

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>

#include <string>

#include "treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "main/analyzer.h"
#include "framework/ips_option.h"

#define SESSION_PRINTABLE    1
#define SESSION_ALL          2

static const char* s_name = "session";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats sessionPerfStats;

static PreprocStats* ssn_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &sessionPerfStats;

    return nullptr;
}
#endif

#define SESSION_PRINTABLE  1
#define SESSION_ALL        2
#define SESSION_BINARY     3

typedef struct _SessionData
{
    int session_flag;
} SessionData;

class SessionOption : public IpsOption
{
public:
    SessionOption(const SessionData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    SessionData config;
};

static FILE *OpenSessionFile(Packet*);
static void DumpSessionData(FILE*, Packet*, SessionData*);

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t SessionOption::hash() const
{
    uint32_t a,b,c;
    const SessionData *data = &config;

    a = data->session_flag;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool SessionOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    SessionOption& rhs = (SessionOption&)ips;
    SessionData *left = (SessionData*)&config;
    SessionData *right = (SessionData*)&rhs.config;

    if (left->session_flag == right->session_flag)
    {
        return true;
    }

    return false;
}

int SessionOption::eval(Packet *p)
{
    SessionData *session_data = &config;
    FILE *session;         /* session file ptr */
    PROFILE_VARS;

    PREPROC_PROFILE_START(sessionPerfStats);

    /* if there's data in this packet */
    if(p != NULL)
    {
        if((p->dsize != 0 && p->data != NULL) || p->frag_flag != 1)
        {
             session = OpenSessionFile(p);

             if(session == NULL)
             {
                 PREPROC_PROFILE_END(sessionPerfStats);
                 return DETECTION_OPTION_MATCH;
             }

             DumpSessionData(session, p, session_data);

             fclose(session);
        }
    }

    PREPROC_PROFILE_END(sessionPerfStats);
    return DETECTION_OPTION_MATCH;
}

//-------------------------------------------------------------------------
// implementation methods
//-------------------------------------------------------------------------

static FILE *OpenSessionFile(Packet *p)
{
    char filename[STD_BUF];
    char session_file[STD_BUF]; /* name of session file */
    sfip_t *dst, *src;

    FILE *ret;

    if(p->frag_flag)
    {
        return NULL;
    }

    memset((char *)session_file, 0, STD_BUF);

    /* figure out which way this packet is headed in relation to the homenet */
    dst = GET_DST_IP(p);
    src = GET_SRC_IP(p);

    const char* addr;

    if(sfip_contains(&snort_conf->homenet, dst) == SFIP_CONTAINS) {
        if(sfip_contains(&snort_conf->homenet, src) == SFIP_NOT_CONTAINS)
        {
            addr = inet_ntoa(GET_SRC_ADDR(p));
        }
        else
        {
            if(p->sp >= p->dp)
            {
                addr = inet_ntoa(GET_SRC_ADDR(p));
            }
            else
            {
                addr = inet_ntoa(GET_DST_ADDR(p));
            }
        }
    }
    else
    {
        if(sfip_contains(&snort_conf->homenet, src) == SFIP_CONTAINS)
        {
            addr = inet_ntoa(GET_DST_ADDR(p));
        }
        else
        {
            if(p->sp >= p->dp)
            {
                addr = inet_ntoa(GET_SRC_ADDR(p));
            }
            else
            {
                addr = inet_ntoa(GET_DST_ADDR(p));
            }
        }
    }
    std::string name;
    const char* log_path = get_instance_file(name, addr);

    /* build the log directory */
    if(mkdir(log_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
    {
        if(errno != EEXIST)
        {
            FatalError("Problem creating directory %s: %s\n",
                       log_path,get_error(errno));
        }
    }

    if(p->sp >= p->dp)
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION:%d-%d", log_path, p->sp, p->dp);

    else
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION:%d-%d", log_path, p->dp, p->sp);


    strncpy(filename, session_file, STD_BUF - 1);
    filename[STD_BUF - 1] = '\0';

    ret = fopen(session_file, "a");

    if(ret == NULL)
    {
        FatalError("OpenSessionFile() => fopen(%s) session file: %s\n",
                   session_file, get_error(errno));
    }

    return ret;

}

static void DumpSessionData(FILE *fp, Packet *p, SessionData *sessionData)
{
    const u_char *idx;
    const u_char *end;
    char conv[] = "0123456789ABCDEF"; /* xlation lookup table */

    if(p->dsize == 0 || p->data == NULL || p->frag_flag)
        return;

    idx = p->data;
    end = idx + p->dsize;

    if(sessionData->session_flag == SESSION_PRINTABLE)
    {
        while(idx != end)
        {
            if((*idx > 0x1f && *idx < 0x7f) || *idx == 0x0a || *idx == 0x0d)
            {
                fputc(*idx, fp);
            }
            idx++;
        }
    }
    else if(sessionData->session_flag == SESSION_BINARY)
    {
        fwrite(p->data, p->dsize, sizeof(char), fp);
    }
    else
    {
        while(idx != end)
        {
            if((*idx > 0x1f && *idx < 0x7f) || *idx == 0x0a || *idx == 0x0d)
            {
                /* Escape all occurences of '\' */
                if(*idx == '\\')
                    fputc('\\', fp);
                fputc(*idx, fp);
            }
            else
            {
                fputc('\\', fp);
                fputc(conv[((*idx&0xFF) >> 4)], fp);
                fputc(conv[((*idx&0xFF)&0x0F)], fp);
            }

            idx++;
        }
    }
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void session_parse(char *data, SessionData *ds_ptr)
{
    /* manipulate the option arguments here */
    while(isspace((int)*data))
        data++;

    if(!strncasecmp(data, "printable", 9))
    {
        ds_ptr->session_flag = SESSION_PRINTABLE;
        return;
    }

    if(!strncasecmp(data, "binary", 6))
    {
        ds_ptr->session_flag = SESSION_BINARY;
        return;
    }

    if(!strncasecmp(data, "all", 3))
    {
        ds_ptr->session_flag = SESSION_ALL;
        return;
    }

    ParseError("invalid session modifier: %s", data);
}

static IpsOption* session_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    SessionData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));

    /* be sure to check that the protocol that is passed in matches the
       transport layer protocol that you're using for this rule! */
    session_parse(data, &ds_ptr);

    return new SessionOption(ds_ptr);
}

static void session_dtor(IpsOption* p)
{
    delete p;
}

static void session_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &sessionPerfStats, ssn_get_profile);
#endif
}

static const IpsApi session_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_LOGGING,
    /*
     * Theoretically we should only allow this plugin to be used when
     * there's a possibility of a session happening (i.e. TCP), but I get
     * enough requests that I'm going to pull the verifier so that things
     * should work for everyone
     */
    1, /*PROTO_BIT__TCP*/0,
    session_ginit,
    nullptr,
    nullptr,
    nullptr,
    session_ctor,
    session_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &session_api.base,
    nullptr
};
#else
const BaseApi* ips_session = &session_api.base;
#endif

