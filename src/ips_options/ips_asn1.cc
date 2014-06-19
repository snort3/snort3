/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2002-2013 Sourcefire, Inc.
 ** Author: Daniel Roelker
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

/**
**  @file        sp_asn1.c
**
**  @author      Daniel Roelker <droelker@sourcefire.com>
**
**  @brief       Decode and detect ASN.1 types, lengths, and data.
**
**  This detection plugin adds ASN.1 detection functions on a per rule
**  basis.  ASN.1 detection plugins can be added by editing this file and
**  providing an interface in the configuration code.
**
**  Detection Plugin Interface:
**
**  asn1: [detection function],[arguments],[offset type],[size]
**
**  Detection Functions:
**
**  bitstring_overflow: no arguments
**  double_overflow:    no arguments
**  oversize_length:    max size (if no max size, then just return value)
**
**  alert udp any any -> any 161 (msg:"foo"; \
**      asn1: oversize_length 10000, absolute_offset 0;)
**
**  alert tcp any any -> any 162 (msg:"foo2"; \
**      asn1: bitstring_overflow, oversize_length 500, relative_offset 7;)
**
**
**  Note that further general information about ASN.1 can be found in
**  the file doc/README.asn1.
*/

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "detection/treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "util.h"
#include "asn1.h"
#include "asn1.h"
#include "asn1_detect.h"
#include "sfhashfcn.h"
#include "detection/detection_util.h"
#include "detection/detection_defines.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "framework/ips_option.h"

#define BITSTRING_OPT  "bitstring_overflow"
#define DOUBLE_OPT     "double_overflow"
#define LENGTH_OPT     "oversize_length"
#define DBL_FREE_OPT   "double_free"

#define ABS_OFFSET_OPT "absolute_offset"
#define REL_OFFSET_OPT "relative_offset"
#define PRINT_OPT      "print"

#define DELIMITERS " ,\t\n"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats asn1PerfStats;

static const char* s_name = "asn1";

static PreprocStats* asn1_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &asn1PerfStats;

    return nullptr;
}
#endif

class Asn1Option : public IpsOption
{
public:
    Asn1Option(ASN1_CTXT& c) : IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    bool is_relative()
    { return ( config.offset_type == REL_OFFSET ); };

    int eval(Cursor&, Packet*);

private:
    ASN1_CTXT config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t Asn1Option::hash() const
{
    uint32_t a,b,c;
    const ASN1_CTXT *data = &config;

    a = data->bs_overflow;
    b = data->double_overflow;
    c = data->print;

    mix(a,b,c);

    a += data->length;
    b += data->max_length;
    c += data->offset;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    a += data->offset_type;

    final(a,b,c);

    return c;
}

bool Asn1Option::operator==(const IpsOption& rhs) const
{
    if ( strcmp(s_name, rhs.get_name()) )
        return false;

    Asn1Option& asn1 = (Asn1Option&)rhs;

    const ASN1_CTXT *left = &config;
    const ASN1_CTXT *right = &asn1.config;

    if ((left->bs_overflow == right->bs_overflow) &&
        (left->double_overflow == right->double_overflow) &&
        (left->print == right->print) &&
        (left->length == right->length) &&
        (left->max_length == right->max_length) &&
        (left->offset == right->offset) &&
        (left->offset_type == right->offset_type))
    {
        return true;
    }

    return false;
}

int Asn1Option::eval(Cursor&, Packet *p)
{
    PROFILE_VARS;

    /*
    **  Failed if there is no data to decode.
    */
    if(!p->data)
        return DETECTION_OPTION_NO_MATCH;

    PREPROC_PROFILE_START(asn1PerfStats);

    if (Asn1DoDetect(p->data, p->dsize, &config, doe_ptr))
    {
        PREPROC_PROFILE_END(asn1PerfStats);
        return DETECTION_OPTION_MATCH;
    }

    PREPROC_PROFILE_END(asn1PerfStats);
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

/*
**  Parse the detection option arguments.
**    - bitstring_overflow
**    - double_overflow
**    - oversize_length
**    - print
**    - abs_offset
**    - rel_offset
*/
static void asn1_parse(char *data, ASN1_CTXT *asn1)
{
    char *pcTok;
    char *endTok;

    if(!data)
        ParseError("No options to 'asn1' detection plugin.");

    char* lasts = nullptr;
    pcTok = strtok_r(data, DELIMITERS, &lasts);

    if(!pcTok)
        ParseError("No options to 'asn1' detection plugin.");

    while(pcTok)
    {
        if(!strcasecmp(pcTok, BITSTRING_OPT))
        {
            asn1->bs_overflow = 1;
        }
        else if(!strcasecmp(pcTok, DOUBLE_OPT))
        {
            asn1->double_overflow = 1;
        }
        else if(!strcasecmp(pcTok, PRINT_OPT))
        {
            asn1->print = 1;
        }
        else if(!strcasecmp(pcTok, LENGTH_OPT))
        {
            long int max_length;
            char *pcEnd;

            pcTok = strtok_r(NULL, DELIMITERS, &lasts);

            if(!pcTok)
                ParseError("No option to '%s' in 'asn1' detection plugin",
                    LENGTH_OPT);

            max_length = SnortStrtolRange(pcTok, &pcEnd, 10, 0, INT32_MAX);

            if ((pcEnd == pcTok) || (*pcEnd) || (errno == ERANGE))
                ParseError(
                    "Negative size, underflow or overflow (of long int) to "
                    "'%s' in 'asn1' detection plugin. Must be positive or zero.",
                    LENGTH_OPT);

            asn1->length = 1;
            asn1->max_length = (unsigned int)max_length;
        }
        else if(!strcasecmp(pcTok, ABS_OFFSET_OPT))
        {
            pcTok = strtok_r(NULL, DELIMITERS, &lasts);
            if(!pcTok)
            {
                ParseError(
                    "No option to '%s' in 'asn1' detection plugin", ABS_OFFSET_OPT);
            }

            asn1->offset_type = ABS_OFFSET;
            asn1->offset = SnortStrtol(pcTok, &endTok, 10);
            if (endTok == pcTok)
            {
                ParseError(
                    "Invalid parameter to '%s' in 'asn1' detection plugin",
                    ABS_OFFSET_OPT);
            }

        }
        else if(!strcasecmp(pcTok, REL_OFFSET_OPT))
        {
            pcTok = strtok_r(NULL, DELIMITERS, &lasts);
            if(!pcTok)
            {
                ParseError(
                    "No option to '%s' in 'asn1' detection plugin",
                    REL_OFFSET_OPT);
            }

            asn1->offset_type = REL_OFFSET;
            asn1->offset = SnortStrtol(pcTok, &endTok, 10);
            if (endTok == pcTok)
            {
                ParseError(
                    "Invalid parameter to '%s' in 'asn1' detection plugin",
                    pcTok);
            }
        }
        else
        {
            ParseError("Unknown ('%s') asn1 detection option.", pcTok);
        }

        pcTok = strtok_r(NULL, DELIMITERS, &lasts);
    }

    return;
}

static IpsOption* asn1_ctor(SnortConfig*, char *data, OptTreeNode*)
{
    ASN1_CTXT asn1;
    memset(&asn1, 0, sizeof(asn1));
    asn1_parse(data, &asn1);
    return new Asn1Option(asn1);
}

static void asn1_dtor(IpsOption* p)
{
    delete p;
}

static void asn1_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &asn1PerfStats, asn1_get_profile);
#endif
}

static const IpsApi asn1_api =
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
    0, 0,
    asn1_ginit,
    nullptr,
    nullptr,
    nullptr,
    asn1_ctor,
    asn1_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &asn1_api.base,
    nullptr
};
#else
const BaseApi* ips_asn1 = &asn1_api.base;
#endif

