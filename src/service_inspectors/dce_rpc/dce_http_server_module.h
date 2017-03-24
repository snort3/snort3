//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 6isco and/or its affiliates. All rights reserved.
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
// dce_http_server_module.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef DCE2_HTTP_SERVER_MODULE_H
#define DCE2_HTTP_SERVER_MODULE_H

#include "dce_common.h"
#include "framework/counts.h"
#include "framework/module.h"
#include "main/thread.h"

struct SnortConfig;

class DceHttpServerModule : public Module
{
public:
    DceHttpServerModule();

    unsigned get_gid() const override
    {
        return GID_DCE2;
    }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
};

#define DCE_HTTP_SERVER_NAME "dce_http_server"
#define DCE_HTTP_SERVER_HELP "dce over http inspection - proxy to/from server"

struct DceHttpServerStats
{
    PegCount http_server_sessions;
    PegCount http_server_session_failures;
};

extern THREAD_LOCAL DceHttpServerStats dce_http_server_stats;

#endif

