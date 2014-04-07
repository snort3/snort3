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

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "snort_types.h"
#include "detection/treenodes.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

#define M_NORMAL  0
#define M_ALL     1
#define M_ANY     2
#define M_NOT     3

#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20
#define R_ECE          0x40  /* ECN echo, RFC 3168 */
#define R_CWR          0x80  /* Congestion Window Reduced, RFC 3168 */

static const char* s_name = "flags";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats tcpFlagsPerfStats;

static PreprocStats* tf_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &tcpFlagsPerfStats;

    return nullptr;
}
#endif

struct TcpFlagCheckData
{
    u_char mode;
    u_char tcp_flags;
    u_char tcp_mask; /* Mask to take away from the flags check */
};

class TcpFlagOption : public IpsOption
{
public:
    TcpFlagOption(const TcpFlagCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    TcpFlagCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t TcpFlagOption::hash() const
{
    uint32_t a,b,c;
    const TcpFlagCheckData *data = &config;

    a = data->mode;
    b = data->tcp_flags || (data->tcp_mask << 8);
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool TcpFlagOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    TcpFlagOption& rhs = (TcpFlagOption&)ips;
    TcpFlagCheckData *left = (TcpFlagCheckData*)&config;
    TcpFlagCheckData *right = (TcpFlagCheckData*)&rhs.config;

    if ((left->mode == right->mode) &&
        (left->tcp_flags == right->tcp_flags) &&
        (left->tcp_mask == right->tcp_mask))
    {
        return true;
    }

    return false;
}

int TcpFlagOption::eval(Packet *p)
{
    TcpFlagCheckData *flagptr = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    u_char tcp_flags;
    PROFILE_VARS;

    PREPROC_PROFILE_START(tcpFlagsPerfStats);

    if(!p->tcph)
    {
        /* if error appeared when tcp header was processed,
         * test fails automagically */
        PREPROC_PROFILE_END(tcpFlagsPerfStats);
        return rval;
    }

    /* the flags we really want to check are all the ones
     */

    tcp_flags = p->tcph->th_flags & (0xFF ^ flagptr->tcp_mask);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "           <!!> CheckTcpFlags: "););

    switch((flagptr->mode))
    {
        case M_NORMAL:
            if(flagptr->tcp_flags == tcp_flags) /* only these set */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got TCP [default] flag match!\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }
            break;

        case M_ALL:
            /* all set */
            if((flagptr->tcp_flags & tcp_flags) == flagptr->tcp_flags)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Got TCP [ALL] flag match!\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }
            break;

        case M_NOT:
            if((flagptr->tcp_flags & tcp_flags) == 0)  /* none set */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got TCP [NOT] flag match!\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "No match\n"););
            }
            break;

        case M_ANY:
            if((flagptr->tcp_flags & tcp_flags) != 0)  /* something set */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got TCP [ANY] flag match!\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }
            break;

        default:  /* Should never see this */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TCP flag check went to default case"
				    " for some silly reason\n"););
            break;
    }

    PREPROC_PROFILE_END(tcpFlagsPerfStats);
    return rval;
}
//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void flags_parse(char *rule, TcpFlagCheckData *idx)
{
    char *fptr;
    char *fend;
    int comma_set = 0;

    fptr = rule;

    /* make sure there is atleast a split pointer */
    if(fptr == NULL)
    {
        ParseError("Flags missing in TCP flag rule");
    }

    while(isspace((u_char) *fptr))
        fptr++;

    if(strlen(fptr) == 0)
    {
        ParseError("Flags missing in TCP flag rule");
    }

    /* find the end of the alert string */
    fend = fptr + strlen(fptr);

    idx->mode = M_NORMAL; /* this is the default, unless overridden */

    while(fptr < fend && comma_set == 0)
    {
        switch(*fptr)
        {
            case 'f':
            case 'F':
                idx->tcp_flags |= R_FIN;
                break;

            case 's':
            case 'S':
                idx->tcp_flags |= R_SYN;
                break;

            case 'r':
            case 'R':
                idx->tcp_flags |= R_RST;
                break;

            case 'p':
            case 'P':
                idx->tcp_flags |= R_PSH;
                break;

            case 'a':
            case 'A':
                idx->tcp_flags |= R_ACK;
                break;

            case 'u':
            case 'U':
                idx->tcp_flags |= R_URG;
                break;

            case '0':
                idx->tcp_flags = 0;
                break;

            case '1': /* reserved bit flags */
            case 'c':
            case 'C':
                idx->tcp_flags |= R_CWR; /* Congestion Window Reduced, RFC 3168 */
                break;

            case '2': /* reserved bit flags */
            case 'e':
            case 'E':
                idx->tcp_flags |= R_ECE; /* ECN echo, RFC 3168 */
                break;

            case '!': /* not, fire if all flags specified are not present,
                         other are don't care */
                idx->mode = M_NOT;
                break;
            case '*': /* star or any, fire if any flags specified are
                         present, other are don't care */
                idx->mode = M_ANY;
                break;
            case '+': /* plus or all, fire if all flags specified are
                         present, other are don't care */
                idx->mode = M_ALL;
                break;
            case ',':
                comma_set = 1;
                break;
            default:
                ParseError(
                    "bad TCP flag = '%c'"
                    "Valid otions: UAPRSFCE or 0 for NO flags (e.g. NULL scan),"
                    " and !, + or * for modifiers",
                    *fptr);
        }

        fptr++;
    }

    while(isspace((u_char) *fptr))
        fptr++;


    /* create the mask portion now */
    while(fptr < fend && comma_set == 1)
    {
        switch(*fptr)
        {
            case 'f':
            case 'F':
                idx->tcp_mask |= R_FIN;
                break;

            case 's':
            case 'S':
                idx->tcp_mask |= R_SYN;
                break;

            case 'r':
            case 'R':
                idx->tcp_mask |= R_RST;
                break;

            case 'p':
            case 'P':
                idx->tcp_mask |= R_PSH;
                break;

            case 'a':
            case 'A':
                idx->tcp_mask |= R_ACK;
                break;

            case 'u':
            case 'U':
                idx->tcp_mask |= R_URG;
                break;

            case '1': /* reserved bit flags */
            case 'c':
            case 'C':
                idx->tcp_mask |= R_CWR; /* Congestion Window Reduced, RFC 3168 */
                break;

            case '2': /* reserved bit flags */
            case 'e':
            case 'E':
                idx->tcp_mask |= R_ECE; /* ECN echo, RFC 3168 */
                break;
            default:
                ParseError("bad TCP flag = '%c'. Valid otions: UAPRSFCE", *fptr);
        }

        fptr++;
    }
}

static IpsOption* flags_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    TcpFlagCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    flags_parse(data, &ds_ptr);
    return new TcpFlagOption(ds_ptr);
}

static void flags_dtor(IpsOption* p)
{
    delete p;
}

static void flags_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &tcpFlagsPerfStats, tf_get_profile);
#endif
}

static const IpsApi flags_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    flags_ginit,
    nullptr,
    nullptr,
    nullptr,
    flags_ctor,
    flags_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &flags_api.base,
    nullptr
};
#else
const BaseApi* ips_flags = &flags_api.base;
#endif

