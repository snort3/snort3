/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "snort_types.h"
#include "decode.h"
#include "log/log.h"
#include "detection/detect.h"

typedef void (*log_func_t)(Packet*);

void CapturePacket();
void DecodeRebuiltPacket (Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, Flow*);
void DetectRebuiltPacket (Packet*);
void LogRebuiltPacket (Packet*);

DAQ_Verdict ProcessPacket(Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, void* ft);

void set_default_policy();

typedef void (*MainHook_f)(Packet*);

enum AnalyzerCommand
{
    AC_NONE,
    AC_STOP,
    AC_PAUSE,
    AC_RESUME,
    AC_ROTATE,
    AC_SWAP,
    AC_MAX
};

class Swapper;

class Analyzer {
public:
    Analyzer(const char* source);

    void operator()(unsigned, Swapper*);

    bool is_done() { return done; };
    uint64_t get_count() { return count; };
    const char* get_source() { return source; };

    // FIXIT add asynchronous response too
    void execute(AnalyzerCommand ac) { command = ac; };
    void set_config(Swapper* ps) { swap = ps; };
    bool swap_pending() { return swap != nullptr; };

    static void set_main_hook(MainHook_f);
    static void ignore(Packet*) { };
    static void print(Packet* p) { PrintPacket(p); };
    static void log(Packet* p) { LogPacket(p); };
    static void inspect(Packet* p) { Inspect(p); };

private:
    void analyze();
    bool handle(AnalyzerCommand);

private:
    bool done;
    uint64_t count;
    const char* source;
    AnalyzerCommand command;
    Swapper* swap;
};

