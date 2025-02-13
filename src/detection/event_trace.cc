//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event_trace.h"

#include "events/event.h"
#include "framework/ips_action.h"
#include "log/text_log.h"
#include "protocols/packet.h"
#include "utils/stats.h"

#include "ips_context.h"
#include "treenodes.h"

using namespace snort;

#define LOG_CHARS 16

static THREAD_LOCAL TextLog* tlog = nullptr;
static THREAD_LOCAL unsigned nEvents = 0;

static void LogBuffer(const char* s, const uint8_t* p, unsigned n)
{
    char hex[(3*LOG_CHARS)+1];
    char txt[LOG_CHARS+1];
    unsigned odx = 0, idx = 0, at = 0;

    if ( !p )
        return;

    const SnortConfig* sc = SnortConfig::get_conf();

    if ( n > sc->event_trace_max )
        n = sc->event_trace_max;

    for ( idx = 0; idx < n; idx++)
    {
        uint8_t byte = p[idx];
        sprintf(hex + 3*odx, "%2.02X ", byte);
        txt[odx++] = isprint(byte) ? byte : '.';

        if ( odx == LOG_CHARS )
        {
            txt[odx] = hex[3*odx] = '\0';
            TextLog_Print(tlog, "%s[%2u] %s %s\n", s, at, hex, txt);
            at = idx + 1;
            odx = 0;
        }
    }
    if ( odx )
    {
        txt[odx] = hex[3*odx] = '\0';
        TextLog_Print(tlog, "%s[%2u] %-48.48s %s\n", s, at, hex, txt);
    }
}

void EventTrace_Log(const Packet* p, const OptTreeNode* otn, IpsAction::Type action)
{
    std::string acts = IpsAction::get_string(action);

    if ( !tlog )
        return;

    TextLog_Print(tlog,
        "\nEvt=%u, Gid=%u, Sid=%u, Rev=%u, Act=%s\n",
        Event::get_curr_seq_num(), otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev, acts.c_str());

    TextLog_Print(tlog,
        "Pkt=" STDu64 ", Sec=%lu.%6lu, Len=%u, Cap=%u\n",
        p->context->packet_number, (long)p->pkth->ts.tv_sec, (long)p->pkth->ts.tv_usec,
        p->pkth->pktlen, p->pktlen);

    TextLog_Print(tlog,
        "Pkt Bits: Flags=0x%X, Proto=0x%X, Err=0x%X\n",
        p->packet_flags, (unsigned)p->proto_bits, (unsigned)p->ptrs.decode_flags);

    TextLog_Print(tlog,
        "Pkt Cnts: Dsz=%u, Alt=%u\n",
        (unsigned)p->dsize, (unsigned)p->alt_dsize);

    uint16_t n = p->alt_dsize > 0 ? p->alt_dsize : p->dsize;
    LogBuffer("Packet", p->data, n);

    nEvents++;
}

void EventTrace_Init()
{
    const SnortConfig* sc = SnortConfig::get_conf();

    if ( sc->event_trace_max > 0 )
    {
        time_t now = time(nullptr);
        char time_buf[26];
        ctime_r(&now, time_buf);

        tlog = TextLog_Init ("event_trace.txt", 4*1024, 8*1024*1024);
        TextLog_Print(tlog, "\nTrace started at %s", time_buf);
        TextLog_Print(tlog, "Trace max_data is %u bytes\n", sc->event_trace_max);
    }
}

void EventTrace_Term()
{
    if ( tlog )
    {
        time_t now = time(nullptr);
        char time_buf[26];
        ctime_r(&now, time_buf);

        TextLog_Print(tlog, "\nTraced %u events\n", nEvents);
        TextLog_Print(tlog, "Trace stopped at %s", time_buf);
        TextLog_Term(tlog);
    }
}

