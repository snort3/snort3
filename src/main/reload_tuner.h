//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifndef RELOAD_TUNER_H
#define RELOAD_TUNER_H

namespace snort
{

class ReloadResourceTuner
{
public:
    static const unsigned RELOAD_MAX_WORK_PER_PACKET = 3;
    // be aggressive when idle as analyzer gets chance once in every second only due to daq timeout
    static const unsigned RELOAD_MAX_WORK_WHEN_IDLE = 32767;

    virtual ~ReloadResourceTuner() = default;

    // returns name of the tuner
    virtual const char* name() const = 0;

    // returns true if resource tuning required, false otherwise
    virtual bool tinit() = 0;

    // each of these returns true if resource tuning is complete, false otherwise
    virtual bool tune_packet_context() = 0;
    virtual bool tune_idle_context() = 0;

    // report progress and/or work left for the tuner
    virtual void report_progress() {}

protected:
    ReloadResourceTuner() = default;

    unsigned max_work = RELOAD_MAX_WORK_PER_PACKET;
    unsigned max_work_idle = RELOAD_MAX_WORK_WHEN_IDLE;
};

class ReloadSwapper : public ReloadResourceTuner
{
public:
    virtual ~ReloadSwapper() override = default;

    // returns name of the tuner
    const char* name() const override
    { return "ReloadSwapper"; }

    // each of these returns true if resource tuning is complete, false otherwise
    bool tune_packet_context() override
    { return true; }
    bool tune_idle_context() override
    { return true; }

    bool tinit() override
    {
        tswap();
        return false;
    }

    virtual void tswap() = 0;

protected:
    ReloadSwapper() = default;
};

}

#endif
