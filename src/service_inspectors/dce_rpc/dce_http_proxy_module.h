//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// dce_http_proxy_module.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef DCE2_HTTP_PROXY_MODULE_H
#define DCE2_HTTP_PROXY_MODULE_H

#include "dce_common.h"
#include "framework/counts.h"
#include "framework/module.h"
#include "main/thread.h"

class DceHttpProxyModule : public snort::Module
{
public:
    DceHttpProxyModule();

    unsigned get_gid() const override
    {
        return GID_DCE2;
    }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return INSPECT; }
};

#define DCE_HTTP_PROXY_NAME "dce_http_proxy"
#define DCE_HTTP_PROXY_HELP "dce over http inspection - client to/from proxy"

struct DceHttpProxyStats
{
    PegCount http_proxy_sessions;
    PegCount http_proxy_session_failures;
};

extern THREAD_LOCAL DceHttpProxyStats dce_http_proxy_stats;

#endif

