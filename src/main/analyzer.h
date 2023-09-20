//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// analyzer.h author Michael Altizer <mialtize@cisco.com>

#ifndef ANALYZER_H
#define ANALYZER_H

// Analyzer provides the packet acquisition and processing loop.  Since it
// runs in a different thread, it also provides a command facility so that
// to control the thread and swap configuration.

#include <daq_common.h>

#include <atomic>
#include <list>
#include <mutex>
#include <queue>
#include <string>

#include "main/snort_types.h"
#include "thread.h"

class ContextSwitcher;
class OopsHandler;
class RetryQueue;
class Swapper;

namespace snort
{
class AnalyzerCommand;
class Flow;
class SFDAQInstance;
struct Packet;
struct SnortConfig;
struct ProfileStats;
}

typedef bool (* MainHook_f)(snort::Packet*);

class UncompletedAnalyzerCommand
{
public:
    UncompletedAnalyzerCommand(snort::AnalyzerCommand* ac, void* acs) : command(ac), state(acs)
    { }

    snort::AnalyzerCommand* command;
    void* state;
};

class Analyzer
{
public:
    enum class State {
        NEW,
        INITIALIZED,
        STARTED,
        RUNNING,
        PAUSED,
        STOPPED,
        FAILED,
        NUM_STATES
    };

    SO_PUBLIC static Analyzer* get_local_analyzer();
    static ContextSwitcher* get_switcher();
    static void set_main_hook(MainHook_f);

    Analyzer(snort::SFDAQInstance*, unsigned id, const char* source, uint64_t msg_cnt = 0);
    ~Analyzer();

    void operator()(Swapper*, uint16_t run_num);

    State get_state() { return state; }
    const char* get_state_string();
    const char* get_source() { return source.c_str(); }

    void set_pause_after_cnt(uint64_t msg_cnt) { pause_after_cnt = msg_cnt; }
    void set_skip_cnt(uint64_t msg_cnt) { skip_cnt = msg_cnt; }

    void execute(snort::AnalyzerCommand*);

    void post_process_packet(snort::Packet*);
    bool process_rebuilt_packet(snort::Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, uint32_t pktlen);
    SO_PUBLIC bool inspect_rebuilt(snort::Packet*);
    void finalize_daq_message(DAQ_Msg_h, DAQ_Verdict);
    void add_to_retry_queue(DAQ_Msg_h, snort::Flow*);

    // Functions called by analyzer commands
    void start();
    void run(bool paused = false);
    void stop();
    void pause();
    void resume(uint64_t msg_cnt);
    void reload_daq();
    void reinit(const snort::SnortConfig*);
    void stop_removed(const snort::SnortConfig*);
    void rotate();
    snort::SFDAQInstance* get_daq_instance() { return daq_instance; }

    bool is_idling() const
    { return idling; }

private:
    void analyze();
    bool handle_command();
    void handle_commands();
    void handle_uncompleted_commands();
    DAQ_RecvStatus process_messages();
    void process_daq_msg(DAQ_Msg_h, bool retry);
    void process_daq_pkt_msg(DAQ_Msg_h, bool retry);
    void post_process_daq_pkt_msg(snort::Packet*);
    void process_retry_queue();
    void set_state(State);
    void idle();
    bool init_privileged();
    void init_unprivileged();
    void term();
    void show_source();
    void add_command_to_uncompleted_queue(snort::AnalyzerCommand*, void*);
    void add_command_to_completed_queue(snort::AnalyzerCommand*);

public:
    std::queue<snort::AnalyzerCommand*> completed_work_queue;
    std::mutex completed_work_queue_mutex;
    std::queue<snort::AnalyzerCommand*> pending_work_queue;

private:
    std::atomic<State> state;
    unsigned id;
    bool exit_requested = false;
    bool idling = false;
    uint64_t exit_after_cnt;
    uint64_t pause_after_cnt = 0;
    uint64_t skip_cnt = 0;
    std::string source;
    snort::SFDAQInstance* daq_instance;
    RetryQueue* retry_queue = nullptr;
    OopsHandler* oops_handler = nullptr;
    ContextSwitcher* switcher = nullptr;
    std::mutex pending_work_queue_mutex;
    std::list<UncompletedAnalyzerCommand*> uncompleted_work_queue;
};

extern THREAD_LOCAL snort::ProfileStats daqPerfStats;

#endif

