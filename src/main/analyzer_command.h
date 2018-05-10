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
// analyzer_command.h author Michael Altizer <mialtize@cisco.com>

#ifndef ANALYZER_COMMANDS_H
#define ANALYZER_COMMANDS_H

#include "main/snort_types.h"

class Analyzer;
class Swapper;

class AnalyzerCommand
{
public:
    virtual ~AnalyzerCommand() = default;
    virtual void execute(Analyzer&) = 0;
    virtual const char* stringify() = 0;
    unsigned get() { return ++ref_count; }
    unsigned put() { return --ref_count; }
private:
    unsigned ref_count = 0;
};

class ACGetStats : public AnalyzerCommand
{
public:
    void execute(Analyzer&) override;
    const char* stringify() override { return "GET_STATS"; }
    ~ACGetStats() override;
};

class ACPause : public AnalyzerCommand
{
public:
    void execute(Analyzer&) override;
    const char* stringify() override { return "PAUSE"; }
};

class ACResume : public AnalyzerCommand
{
public:
    void execute(Analyzer&) override;
    const char* stringify() override { return "RESUME"; }
};

class ACRotate : public AnalyzerCommand
{
public:
    void execute(Analyzer&) override;
    const char* stringify() override { return "ROTATE"; }
};

class ACRun : public AnalyzerCommand
{
public:
    ACRun() = delete;
    ACRun(bool is_paused = false ) { paused = is_paused; }
    void execute(Analyzer&) override;
    const char* stringify() override { return "RUN"; }
private:
    bool paused = false;
};

class ACStart : public AnalyzerCommand
{
public:
    void execute(Analyzer&) override;
    const char* stringify() override { return "START"; }
};

class ACStop : public AnalyzerCommand
{
public:
    void execute(Analyzer&) override;
    const char* stringify() override { return "STOP"; }
};

class ACSwap : public AnalyzerCommand
{
public:
    ACSwap() = delete;
    ACSwap(Swapper* ps);
    void execute(Analyzer&) override;
    const char* stringify() override { return "SWAP"; }
    ~ACSwap() override;
private:
    Swapper *ps;
};

class ACDAQSwap : public AnalyzerCommand
{
public:
    void execute(Analyzer&) override;
    const char* stringify() override { return "DAQ_SWAP"; }
    ~ACDAQSwap() override;
};

namespace snort
{
SO_PUBLIC void main_broadcast_command(AnalyzerCommand* ac, bool from_shell = false);   // From main.cc
}

#endif

