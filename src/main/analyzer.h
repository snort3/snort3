//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// analyzer.h author Russ Combs <rucombs@cisco.com>

#ifndef ANALYZER_H
#define ANALYZER_H

// Analyzer provides the packet acquisition and processing loop.  Since it
// runs in a different thread, it also provides a command facility so that
// to control the thread and swap configuration.

#include <atomic>
#include <mutex>
#include <queue>
#include <string>

class AnalyzerCommand;
class Swapper;

namespace snort
{
class SFDAQInstance;
}

class Analyzer
{
public:
    enum class State {
        NEW,
        INITIALIZED,
        STARTED,
        RUNNING,
        PAUSED,
        STOPPED
    };
    Analyzer(unsigned id, const char* source);

    void operator()(Swapper*, uint16_t run_num);

    State get_state() { return state; }
    const char* get_state_string();
    const char* get_source() { return source.c_str(); }

    void execute(AnalyzerCommand*);

    bool requires_privileged_start() { return privileged_start; }

    // Functions called by analyzer commands
    void start();
    void run(bool paused = false);
    void stop();
    void pause();
    void resume();
    void reload_daq();

private:
    void analyze();
    bool handle_command();
    void set_state(State);

public:
    std::queue<AnalyzerCommand*> completed_work_queue;
    std::mutex completed_work_queue_mutex;
    std::queue<AnalyzerCommand*> pending_work_queue;

private:
    std::atomic<State> state;
    std::atomic<bool> privileged_start;

    unsigned id;
    bool exit_requested;

    std::string source;
    snort::SFDAQInstance* daq_instance;

    std::mutex pending_work_queue_mutex;
};

#endif

