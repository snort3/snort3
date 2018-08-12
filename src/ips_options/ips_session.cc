//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
 *                 chars in "\xNN" hexadecimal format
 *
 * Effect:
 *
 * Warning, this plugin may slow Snort *way* down!
 *
 */
// FIXIT-L delete this (sp_session) and use session tag instead

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;

#define s_name "session"

static THREAD_LOCAL ProfileStats sessionPerfStats;

#define SESSION_PRINTABLE   1
#define SESSION_BINARY      2
#define SESSION_ALL         3

struct SessionData
{
    int session_flag;
};

class SessionOption : public IpsOption
{
public:
    SessionOption(const SessionData& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    SessionData config;
};

static FILE* OpenSessionFile(Packet*);
static void DumpSessionData(FILE*, Packet*, SessionData*);

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t SessionOption::hash() const
{
    uint32_t a,b,c;
    const SessionData* data = &config;

    a = data->session_flag;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool SessionOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SessionOption& rhs = (const SessionOption&)ips;
    const SessionData* left = &config;
    const SessionData* right = &rhs.config;

    if (left->session_flag == right->session_flag)
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus SessionOption::eval(Cursor&, Packet* p)
{
    Profile profile(sessionPerfStats);

    if ( !p->dsize || !p->data )
        return MATCH;

    if ( p->is_fragment() )
        return MATCH;

    // FIXIT-L should wrap file open/close in a class to ensure cleanup
    {
        FILE* session = OpenSessionFile(p);

        if ( !session )
            return MATCH;

        DumpSessionData(session, p, &config);
        fclose(session);
    }

    return MATCH;
}

//-------------------------------------------------------------------------
// implementation methods
//-------------------------------------------------------------------------

static FILE* OpenSessionFile(Packet* p)
{
    char filename[STD_BUF];
    char session_file[STD_BUF]; /* name of session file */
    const SfIp* dst, * src;

    FILE* ret;

    if (p->ptrs.decode_flags & DECODE_FRAG)
    {
        return nullptr;
    }

    memset((char*)session_file, 0, STD_BUF);

    /* figure out which way this packet is headed in relation to the homenet */
    dst = p->ptrs.ip_api.get_dst();
    src = p->ptrs.ip_api.get_src();

    SfIpString addr;

    if (SnortConfig::get_conf()->homenet.contains(dst) == SFIP_CONTAINS)
    {
        if (SnortConfig::get_conf()->homenet.contains(src) == SFIP_NOT_CONTAINS)
        {
            p->ptrs.ip_api.get_src()->ntop(addr);
        }
        else
        {
            if (p->ptrs.sp >= p->ptrs.dp)
            {
                p->ptrs.ip_api.get_src()->ntop(addr);
            }
            else
            {
                p->ptrs.ip_api.get_dst()->ntop(addr);
            }
        }
    }
    else
    {
        if (SnortConfig::get_conf()->homenet.contains(src) == SFIP_CONTAINS)
        {
            p->ptrs.ip_api.get_dst()->ntop(addr);
        }
        else
        {
            if (p->ptrs.sp >= p->ptrs.dp)
            {
                p->ptrs.ip_api.get_src()->ntop(addr);
            }
            else
            {
                p->ptrs.ip_api.get_dst()->ntop(addr);
            }
        }
    }
    std::string name;
    const char* log_path = get_instance_file(name, addr);

    /* build the log directory */
    if (mkdir(log_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
    {
        if (errno != EEXIST)
        {
            FatalError("Problem creating directory %s: %s\n",
                log_path,get_error(errno));
        }
    }

    if (p->ptrs.sp >= p->ptrs.dp)
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION:%d-%d", log_path, p->ptrs.sp, p->ptrs.dp);


    else
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION:%d-%d", log_path, p->ptrs.dp, p->ptrs.sp);


    strncpy(filename, session_file, STD_BUF - 1);
    filename[STD_BUF - 1] = '\0';

    ret = fopen(session_file, "a");

    if (ret == nullptr)
    {
        FatalError("OpenSessionFile() => fopen(%s) session file: %s\n",
            session_file, get_error(errno));
    }

    return ret;
}

static void DumpSessionData(FILE* fp, Packet* p, SessionData* sessionData)
{
    const uint8_t* idx;
    const uint8_t* end;
    char conv[] = "0123456789ABCDEF"; /* xlation lookup table */

    if (p->dsize == 0 || p->data == nullptr || (p->ptrs.decode_flags & DECODE_FRAG))
        return;

    idx = p->data;
    end = idx + p->dsize;

    if (sessionData->session_flag == SESSION_PRINTABLE)
    {
        while (idx != end)
        {
            if ((*idx > 0x1f && *idx < 0x7f) || *idx == 0x0a || *idx == 0x0d)
            {
                fputc(*idx, fp);
            }
            idx++;
        }
    }
    else if (sessionData->session_flag == SESSION_BINARY)
    {
        fwrite(p->data, p->dsize, sizeof(char), fp);
    }
    else
    {
        while (idx != end)
        {
            if ((*idx > 0x1f && *idx < 0x7f) || *idx == 0x0a || *idx == 0x0d)
            {
                /* Escape all occurrences of '\' */
                if (*idx == '\\')
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
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~mode", Parameter::PT_ENUM, "printable|binary|all", nullptr,
      "output format" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check user data from TCP sessions"

class SsnModule : public Module
{
public:
    SsnModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &sessionPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    SessionData data;
};

bool SsnModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool SsnModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~mode") )
        data.session_flag = v.get_long() + 1;

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new SsnModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* session_ctor(Module* p, OptTreeNode*)
{
    SsnModule* m = (SsnModule*)p;
    return new SessionOption(m->data);
}

static void session_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi session_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_LOGGING,
    /*
     * Theoretically we should only allow this plugin to be used when
     * there's a possibility of a session happening (i.e. TCP), but I get
     * enough requests that I'm going to pull the verifier so that things
     * should work for everyone
     */
    1, /*PROTO_BIT__TCP*/ 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    session_ctor,
    session_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_session[] =
#endif
{
    &session_api.base,
    nullptr
};

