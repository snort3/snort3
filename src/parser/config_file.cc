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

#include "config_file.h"

#include <cstring>

#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/policy.h"

#include "mstring.h"

#define CHECKSUM_MODE_OPT__ALL      "all"
#define CHECKSUM_MODE_OPT__NONE     "none"
#define CHECKSUM_MODE_OPT__IP       "ip"
#define CHECKSUM_MODE_OPT__NO_IP    "noip"
#define CHECKSUM_MODE_OPT__TCP      "tcp"
#define CHECKSUM_MODE_OPT__NO_TCP   "notcp"
#define CHECKSUM_MODE_OPT__UDP      "udp"
#define CHECKSUM_MODE_OPT__NO_UDP   "noudp"
#define CHECKSUM_MODE_OPT__ICMP     "icmp"
#define CHECKSUM_MODE_OPT__NO_ICMP  "noicmp"

static std::string lua_conf;
static std::string snort_conf_dir;

const char* get_snort_conf()
{ return lua_conf.c_str(); }

const char* get_snort_conf_dir()
{ return snort_conf_dir.c_str(); }

static int GetChecksumFlags(const char* args)
{
    char** toks;
    int num_toks;
    int i;
    int negative_flags = 0;
    int positive_flags = 0;
    int got_positive_flag = 0;
    int got_negative_flag = 0;
    int ret_flags = 0;

    if (args == nullptr)
        return CHECKSUM_FLAG__ALL;

    toks = snort::mSplit(args, " \t", 10, &num_toks, 0);
    for (i = 0; i < num_toks; i++)
    {
        if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__ALL) == 0)
        {
            positive_flags = CHECKSUM_FLAG__ALL;
            negative_flags = 0;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NONE) == 0)
        {
            positive_flags = 0;
            negative_flags = CHECKSUM_FLAG__ALL;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__IP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__IP;
            negative_flags &= ~CHECKSUM_FLAG__IP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_IP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__IP;
            negative_flags |= CHECKSUM_FLAG__IP;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__TCP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__TCP;
            negative_flags &= ~CHECKSUM_FLAG__TCP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_TCP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__TCP;
            negative_flags |= CHECKSUM_FLAG__TCP;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__UDP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__UDP;
            negative_flags &= ~CHECKSUM_FLAG__UDP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_UDP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__UDP;
            negative_flags |= CHECKSUM_FLAG__UDP;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__ICMP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__ICMP;
            negative_flags &= ~CHECKSUM_FLAG__ICMP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_ICMP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__ICMP;
            negative_flags |= CHECKSUM_FLAG__ICMP;
            got_negative_flag = 1;
        }
        else
        {
            snort::ParseError("unknown command line checksum option: %s.", toks[i]);
            return ret_flags;
        }
    }

    /* Invert the negative flags with all checksums */
    negative_flags ^= CHECKSUM_FLAG__ALL;
    negative_flags &= CHECKSUM_FLAG__ALL;

    if (got_positive_flag && got_negative_flag)
    {
        /* If we got both positive and negative flags just take the
         * combination of the two */
        ret_flags = positive_flags & negative_flags;
    }
    else if (got_positive_flag)
    {
        /* If we got a positive flag assume the user wants checksums
         * to be cleared */
        ret_flags = positive_flags;
    }
    else  /* got a negative flag */
    {
        /* If we got a negative flag assume the user thinks all
         * checksums are on */
        ret_flags = negative_flags;
    }

    snort::mSplitFree(&toks, num_toks);
    return ret_flags;
}

void ConfigChecksumDrop(const char* args)
{
    NetworkPolicy* policy = snort::get_network_policy();
    policy->checksum_drop = GetChecksumFlags(args);
}

void ConfigChecksumMode(const char* args)
{
    NetworkPolicy* policy = snort::get_network_policy();
    policy->checksum_eval = GetChecksumFlags(args);
}

void config_conf(const char* val)
{
    lua_conf = val;
    SetSnortConfDir(lua_conf.c_str());
    snort::Snort::set_main_hook(snort::DetectionEngine::inspect);
}

void SetSnortConfDir(const char* file)
{
    /* extract the config directory from the config filename */
    if ( file )
    {
        const char* path_sep = strrchr(file, '/');

        /* is there a directory separator in the filename */
        if (path_sep != nullptr)
        {
            path_sep++;  /* include path separator */
            snort_conf_dir.assign(file, path_sep - file);
        }
        else
        {
            snort_conf_dir = "./";
        }
    }
}

