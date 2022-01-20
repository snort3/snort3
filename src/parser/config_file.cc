//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include <sstream>
#include <string>

#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/analyzer.h"
#include "main/policy.h"

using namespace snort;

static std::string lua_conf;
static std::string snort_conf_dir;

const char* get_snort_conf()
{ return lua_conf.c_str(); }

const char* get_snort_conf_dir()
{ return snort_conf_dir.c_str(); }

static int GetChecksumFlags(const char* args)
{
    int negative_flags = 0;
    int positive_flags = 0;
    int got_positive_flag = 0;
    int got_negative_flag = 0;
    int ret_flags = 0;

    if (args == nullptr)
        return CHECKSUM_FLAG__ALL;

    std::stringstream ss(args);
    std::string tok;

    while ( ss >> tok )
    {
        if ( tok == "all" )
        {
            positive_flags = CHECKSUM_FLAG__ALL;
            negative_flags = 0;
            got_positive_flag = 1;
        }
        else if ( tok == "none" )
        {
            positive_flags = 0;
            negative_flags = CHECKSUM_FLAG__ALL;
            got_negative_flag = 1;
        }
        else if ( tok == "ip" )
        {
            positive_flags |= CHECKSUM_FLAG__IP;
            negative_flags &= ~CHECKSUM_FLAG__IP;
            got_positive_flag = 1;
        }
        else if ( tok == "noip" )
        {
            positive_flags &= ~CHECKSUM_FLAG__IP;
            negative_flags |= CHECKSUM_FLAG__IP;
            got_negative_flag = 1;
        }
        else if ( tok == "tcp" )
        {
            positive_flags |= CHECKSUM_FLAG__TCP;
            negative_flags &= ~CHECKSUM_FLAG__TCP;
            got_positive_flag = 1;
        }
        else if ( tok == "notcp" )
        {
            positive_flags &= ~CHECKSUM_FLAG__TCP;
            negative_flags |= CHECKSUM_FLAG__TCP;
            got_negative_flag = 1;
        }
        else if ( tok == "udp" )
        {
            positive_flags |= CHECKSUM_FLAG__UDP;
            negative_flags &= ~CHECKSUM_FLAG__UDP;
            got_positive_flag = 1;
        }
        else if ( tok == "noudp" )
        {
            positive_flags &= ~CHECKSUM_FLAG__UDP;
            negative_flags |= CHECKSUM_FLAG__UDP;
            got_negative_flag = 1;
        }
        else if ( tok == "icmp" )
        {
            positive_flags |= CHECKSUM_FLAG__ICMP;
            negative_flags &= ~CHECKSUM_FLAG__ICMP;
            got_positive_flag = 1;
        }
        else if ( tok == "noicmp" )
        {
            positive_flags &= ~CHECKSUM_FLAG__ICMP;
            negative_flags |= CHECKSUM_FLAG__ICMP;
            got_negative_flag = 1;
        }
        else
        {
            ParseError("unknown command line checksum option: %s.", tok.c_str());
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

    return ret_flags;
}

void ConfigChecksumDrop(const char* args)
{
    NetworkPolicy* policy = get_network_policy();
    policy->checksum_drop = GetChecksumFlags(args);
}

void ConfigChecksumMode(const char* args)
{
    NetworkPolicy* policy = get_network_policy();
    policy->checksum_eval = GetChecksumFlags(args);
}

void config_conf(const char* val)
{
    lua_conf = val;
    SetSnortConfDir(lua_conf.c_str());
    Analyzer::set_main_hook(DetectionEngine::inspect);
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

