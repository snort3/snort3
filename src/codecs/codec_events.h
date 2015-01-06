//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// codec_events.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef CODECS_CODEC_EVENTS_H
#define CODECS_CODEC_EVENTS_H

#include "framework/codec.h"
#include "codecs/codec_module.h"
#include "events/event_queue.h"


namespace codec_events
{

inline void decoder_event(const CodecData& codec, const CodecSid sid)
{
    if ( codec.codec_flags & CODEC_STREAM_REBUILT )
        return;

    SnortEventqAdd(GID_DECODE, sid);
}

} //namespace codec_events


#endif

