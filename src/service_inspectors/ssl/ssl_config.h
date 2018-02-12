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

#ifndef SSL_CONFIG_H
#define SSL_CONFIG_H

// Configuration for SSL service inspector

#include "framework/counts.h"

struct SSL_PROTO_CONF
{
    bool trustservers;
    int max_heartbeat_len;
};

struct SslStats
{
    PegCount packets;
    PegCount decoded;
    PegCount hs_chello;
    PegCount hs_shello;
    PegCount hs_cert;
    PegCount hs_sdone;
    PegCount hs_ckey;
    PegCount hs_skey;
    PegCount cipher_change;
    PegCount hs_finished;
    PegCount capp;
    PegCount sapp;
    PegCount alerts;
    PegCount unrecognized;
    PegCount completed_hs;
    PegCount bad_handshakes;
    PegCount stopped;
    PegCount disabled;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

extern const PegInfo ssl_peg_names[];
extern THREAD_LOCAL SslStats sslstats;

#endif
