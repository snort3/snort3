//--------------------------------------------------------------------------
// Copyright (C) 2021 Cisco and/or its affiliates. All rights reserved.
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
// ips_vba_data.h author Amarnath Nayak <amarnaya@cisco.com>

#include "detection/detection_engine.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "helpers/literal_search.h"
#include "profiler/profiler.h"
#include "trace/trace.h"

#define s_name "vba_data"
#define s_help \
    "rule option to set the detection cursor to the MS Office Visual Basic for Applications macros buffer"

static THREAD_LOCAL snort::ProfileStats vbaDataPerfStats;

extern THREAD_LOCAL const snort::Trace* vba_data_trace;

extern snort::LiteralSearch::Handle* search_handle ;
extern const snort::LiteralSearch* searcher ;

class VbaDataOption : public snort::IpsOption
{
public:
    VbaDataOption() : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_SET) { }

    snort::CursorActionType get_cursor_type() const override;

    snort::IpsOption::EvalStatus eval(Cursor&, snort::Packet*) override;
};

class VbaDataModule : public snort::Module
{
public:
    VbaDataModule() : Module(s_name, s_help) { }
    ~VbaDataModule() override;

    bool end(const char*, int, snort::SnortConfig*) override;

    snort::ProfileStats* get_profile() const override;

    snort::Module::Usage get_usage() const override
    {return DETECT;}

    void set_trace(const snort::Trace* trace) const override;

    const snort::TraceOption* get_trace_options() const override;
};

