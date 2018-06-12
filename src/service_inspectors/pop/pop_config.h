//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
//

#ifndef POP_CONFIG_H
#define POP_CONFIG_H
// Configuration for Pop service inspector

#include "mime/file_mime_process.h"

struct POP_PROTO_CONF
{
    snort::DecodeConfig decode_conf;
    MailLogConfig log_config;
};

struct PopStats
{
    PegCount packets;
    PegCount sessions;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    MimeStats mime_stats;
};

extern const PegInfo pop_peg_names[];
extern THREAD_LOCAL PopStats popstats;

#endif

