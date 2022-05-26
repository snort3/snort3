//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
// analyzer_command.h author Michael Altizer <mialtize@cisco.com>

#ifndef ANALYZER_COMMANDS_H
#define ANALYZER_COMMANDS_H

#include <cstdarg>
#include <vector>

#include "main/snort_types.h"

class Analyzer;
class ControlConn;
class Swapper;

namespace snort
{
class ScratchAllocator;
struct SnortConfig;

class SFDAQInstance;

class AnalyzerCommand
{
public:
    AnalyzerCommand() : AnalyzerCommand(nullptr)
    { }
    explicit AnalyzerCommand(ControlConn* conn) : ctrlcon(conn)
    { }
    virtual ~AnalyzerCommand() = default;
    virtual bool execute(Analyzer&, void**) = 0;
    virtual bool need_update_reload_id() const
    { return false; }
    virtual const char* stringify() = 0;
    unsigned get() { return ++ref_count; }
    unsigned put() { return --ref_count; }
    SO_PUBLIC void log_message(const char* format, ...) __attribute__((format (printf, 2, 3)));
    SO_PUBLIC static void log_message(ControlConn*, const char* format, ...) __attribute__((format (printf, 2, 3)));
    SO_PUBLIC static snort::SFDAQInstance* get_daq_instance(Analyzer& analyzer);

    ControlConn* ctrlcon;

private:
    static void log_message(ControlConn*, const char* format, va_list& ap);
    unsigned ref_count = 0;
};
}

class ACGetStats : public snort::AnalyzerCommand
{
public:
    ACGetStats(ControlConn* conn) : AnalyzerCommand(conn)
    { }
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "GET_STATS"; }
    ~ACGetStats() override;
};

typedef enum clear_counter_type
{
    TYPE_UNKNOWN=-1,
    TYPE_DAQ=0,
    TYPE_MODULE,
    TYPE_APPID,
    TYPE_FILE_ID,
    TYPE_SNORT,
    TYPE_HA
} clear_counter_type_t;

// FIXIT-M Will replace this vector with an unordered map of
// <clear_counter_type, clear_counter_type_string_map> when
// will come up with more granular form of clearing module stats.
static std::vector<const char*> clear_counter_type_string_map
{
    "daq",
    "module",
    "appid",
    "file_id",
    "snort",
    "high_availability"
};

class ACResetStats : public snort::AnalyzerCommand
{
public:
    explicit ACResetStats(clear_counter_type_t requested_type);
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "RESET_STATS"; }
private:
    clear_counter_type_t requested_type;
};

class ACPause : public snort::AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "PAUSE"; }
};

class ACResume : public snort::AnalyzerCommand
{
public:
    ACResume(uint64_t msg_cnt): msg_cnt(msg_cnt) { }
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "RESUME"; }
private:
    uint64_t msg_cnt;
};

class ACRotate : public snort::AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "ROTATE"; }
};

class ACRun : public snort::AnalyzerCommand
{
public:
    ACRun() = delete;
    ACRun(bool is_paused = false ) { paused = is_paused; }
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "RUN"; }
private:
    bool paused = false;
};

class ACStart : public snort::AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "START"; }
};

class ACStop : public snort::AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "STOP"; }
};

class ACSwap : public snort::AnalyzerCommand
{
public:
    ACSwap() = delete;
    ACSwap(Swapper* ps, ControlConn* conn) : AnalyzerCommand(conn), ps(ps)
    { }
    bool execute(Analyzer&, void**) override;
    bool need_update_reload_id() const override
    { return true; }
    const char* stringify() override { return "SWAP"; }
    ~ACSwap() override;
private:
    Swapper *ps;
};

class ACHostAttributesSwap : public snort::AnalyzerCommand
{
public:
    ACHostAttributesSwap(ControlConn* conn) : AnalyzerCommand(conn)
    { }
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "HOST_ATTRIBUTES_SWAP"; }
    ~ACHostAttributesSwap() override;
};

class ACDAQSwap : public snort::AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "DAQ_SWAP"; }
    ~ACDAQSwap() override;
};

class ACScratchUpdate : public snort::AnalyzerCommand
{
public:
    ACScratchUpdate(snort::SnortConfig* sc, std::vector<snort::ScratchAllocator*>& handlers,
        ControlConn* conn) : AnalyzerCommand(conn), sc(sc), handlers(handlers)
    { }
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "SCRATCH_UPDATE"; }
    ~ACScratchUpdate() override;
private:
    snort::SnortConfig* sc;
    std::vector<snort::ScratchAllocator*>& handlers;
};

namespace snort
{
// from main.cc
#ifdef REG_TEST
void main_unicast_command(AnalyzerCommand*, unsigned target, ControlConn* = nullptr);
#endif
SO_PUBLIC void main_broadcast_command(snort::AnalyzerCommand*, ControlConn* = nullptr);
}

#endif

