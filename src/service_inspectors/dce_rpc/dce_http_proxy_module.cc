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

// dce_http_proxy_module.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_http_proxy_module.h"

static const PegInfo dce_http_proxy_pegs[] =
{
    { CountType::SUM, "http_proxy_sessions", "successful http proxy sessions" },
    { CountType::SUM, "http_proxy_session_failures", "failed http proxy sessions" },
    { CountType::END, nullptr, nullptr }
};

DceHttpProxyModule::DceHttpProxyModule() : Module(DCE_HTTP_PROXY_NAME, DCE_HTTP_PROXY_HELP)
{
}

const PegInfo* DceHttpProxyModule::get_pegs() const
{
    return dce_http_proxy_pegs;
}

PegCount* DceHttpProxyModule::get_counts() const
{
    return (PegCount*)&dce_http_proxy_stats;
}
