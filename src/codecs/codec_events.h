/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef CODEC_EVENTS_H
#define CODEC_EVENTS_H


#define EVARGS(ID) DECODE_ ## ID, DECODE_ ## ID ## _STR

#include <array>

// included for DECODE_INDEX_MAX
#include "detection/generators.h"
#include "utils/sfActionQueue.h"
#include "network_inspectors/normalize/normalize.h"
#include "protocols/packet.h"
#include "time/profiler.h"


// forward declarations
typedef void (*void_callback_f)(void*);


class CodecEvents
{
public:

    static void decoder_event (Packet *p, int sid, const char *str);
    static void DecoderAlertEncapsulated(
        Packet *p, int type, const char *str, const uint8_t *pkt, uint32_t len);


    static void decoder_init(unsigned max);
    static void decoder_term(void);
    static void decoder_exec(void);
    static void EnableDecodeRules();
    static void DisableDecodeRules();
    static void UpdateDecodeRule(uint32_t sid, bool on);
    static void queue_exec_drop(void_callback_f, Packet* p);

    static void DecoderOptEvent (
        Packet *p, int sid, const char *str, void_callback_f );

    static bool event_enabled(int sid);
    static void execIcmpChksmDrop (void*);

    static void queueDecoderEvent(
                    unsigned int gid, 
                    unsigned int sid,
                    unsigned int rev,
                    unsigned int classification,
                    unsigned int pri,
                    const char *msg,
                    void *rule_info);


    static int ScNormalDrop (NormFlags nf);
    static void execHopDrop (void *data);
    static void execTtlDrop (void *data);
    static void execDecoderEvent(void *data);
private:




//static std::array<bool, DECODE_INDEX_MAX> decodeRuleEnabled;
};

static inline
void DecoderEvent(Packet *p, int sid, const char *str){
    CodecEvents::decoder_event(p, sid, str);
};

static inline
bool Event_Enabled(int sid){
    CodecEvents::event_enabled(sid);
}


#endif /* CODEC_EVENTS_H */
