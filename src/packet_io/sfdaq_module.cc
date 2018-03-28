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

// sfdaq_module.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfdaq_module.h"

#include <cassert>

#include "log/messages.h"
#include "main/snort_config.h"

#include "active.h"
#include "sfdaq.h"
#include "sfdaq_config.h"
#include "trough.h"

using namespace snort;

#define sfdaq_help "configure packet acquisition interface"

struct DAQStats
{
    PegCount pcaps;
    PegCount received;
    PegCount analyzed;
    PegCount dropped;
    PegCount filtered;
    PegCount outstanding;
    PegCount injected;
    PegCount verdicts[MAX_DAQ_VERDICT];
    PegCount internal_blacklist;
    PegCount internal_whitelist;
    PegCount skipped;
    PegCount idle;
    PegCount rx_bytes;
};

const PegInfo daq_names[] =
{
    { CountType::MAX, "pcaps", "total files and interfaces processed" },
    { CountType::SUM, "received", "total packets received from DAQ" },
    { CountType::SUM, "analyzed", "total packets analyzed from DAQ" },
    { CountType::SUM, "dropped", "packets dropped" },
    { CountType::SUM, "filtered", "packets filtered out" },
    { CountType::SUM, "outstanding", "packets unprocessed" },
    { CountType::SUM, "injected", "active responses or replacements" },
    { CountType::SUM, "allow", "total allow verdicts" },
    { CountType::SUM, "block", "total block verdicts" },
    { CountType::SUM, "replace", "total replace verdicts" },
    { CountType::SUM, "whitelist", "total whitelist verdicts" },
    { CountType::SUM, "blacklist", "total blacklist verdicts" },
    { CountType::SUM, "ignore", "total ignore verdicts" },
    { CountType::SUM, "retry", "total retry verdicts" },

    // FIXIT-L these are not exactly DAQ counts - but they are related
    { CountType::SUM, "internal_blacklist",
        "packets blacklisted internally due to lack of DAQ support" },
    { CountType::SUM, "internal_whitelist",
        "packets whitelisted internally due to lack of DAQ support" },
    { CountType::SUM, "skipped", "packets skipped at startup" },
    { CountType::SUM, "idle", "attempts to acquire from DAQ without available packets" },
    { CountType::SUM, "rx_bytes", "total bytes received" },
    { CountType::END, nullptr, nullptr }
};

static THREAD_LOCAL DAQStats stats;

static const Parameter string_list_param[] =
{
    { "str", Parameter::PT_STRING, nullptr, nullptr, "string parameter" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter instance_params[] =
{
    { "id", Parameter::PT_INT, "0:", nullptr, "instance ID (required)" },
    { "input_spec", Parameter::PT_STRING, nullptr, nullptr, "input specification" },
    { "variables", Parameter::PT_LIST, string_list_param, nullptr, "DAQ variables" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "module_dirs", Parameter::PT_LIST, string_list_param, nullptr, "directories to search for DAQ modules" },
    { "input_spec", Parameter::PT_STRING, nullptr, nullptr, "input specification" },
    { "module", Parameter::PT_STRING, nullptr, nullptr, "DAQ module to use" },
    { "variables", Parameter::PT_LIST, string_list_param, nullptr, "DAQ variables" },
    { "instances", Parameter::PT_LIST, instance_params, nullptr, "DAQ instance overrides" },
    { "snaplen", Parameter::PT_INT, "0:65535", nullptr, "set snap length (same as -s)" },
    { "no_promisc", Parameter::PT_BOOL, nullptr, "false", "whether to put DAQ device into promiscuous mode" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

SFDAQModule::SFDAQModule() : Module("daq", sfdaq_help, s_params)
{
    config = nullptr;
    instance_config = nullptr;
}


bool SFDAQModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if (!strcmp(fqn, "daq"))
        config = new SFDAQConfig();

    else if (!strcmp(fqn, "daq.instances"))
    {
        if (idx == 0)
            return true;

        assert(!instance_config);
        instance_config = new SFDAQInstanceConfig();

        instance_id = -1;
    }
    return true;
}

bool SFDAQModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    if (!strcmp(fqn, "daq.module_dirs"))
    {
        config->add_module_dir(v.get_string());
    }
    else if (!strcmp(fqn, "daq.module"))
    {
        config->set_module_name(v.get_string());
    }
    else if (!strcmp(fqn, "daq.input_spec"))
    {
        config->set_input_spec(v.get_string());
    }
    else if (!strcmp(fqn, "daq.variables"))
    {
        config->set_variable(v.get_string());
    }
    else if (!strcmp(fqn, "daq.snaplen"))
    {
        config->set_mru_size(v.get_long());
    }
    else if (!strcmp(fqn, "daq.no_promisc"))
    {
        v.update_mask(sc->run_flags, RUN_FLAG__NO_PROMISCUOUS);
    }
    else if (!strcmp(fqn, "daq.instances.id"))
    {
        instance_id = v.get_long();
    }
    else if (!strcmp(fqn, "daq.instances.input_spec"))
    {
        instance_config->set_input_spec(v.get_string());
    }
    else if (!strcmp(fqn, "daq.instances.variables"))
    {
        instance_config->set_variable(v.get_string());
    }

    return true;
}

bool SFDAQModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if (!strcmp(fqn, "daq.instances"))
    {
        if (idx == 0)
            return true;

        if (instance_id < 0 or config->instances[instance_id])
        {
            ParseError("%s - duplicate or no DAQ instance ID specified", fqn);
            delete instance_config;
            instance_config = nullptr;
            return false;
        }
        config->instances[instance_id] = instance_config;
        instance_config = nullptr;
    }
    else if (!strcmp(fqn, "daq"))
    {
        if ( sc->daq_config )
            delete sc->daq_config;

        sc->daq_config = config;
        config = nullptr;
    }

    return true;
}

const PegInfo* SFDAQModule::get_pegs() const
{
    return daq_names;
}

PegCount* SFDAQModule::get_counts() const
{
    return (PegCount*) &stats;
}

static DAQ_Stats_t operator-(const DAQ_Stats_t& left, const DAQ_Stats_t& right)
{
    DAQ_Stats_t ret;

    ret.hw_packets_received = left.hw_packets_received - right.hw_packets_received;
    ret.hw_packets_dropped = left.hw_packets_dropped - right.hw_packets_dropped;
    ret.packets_received = left.packets_received - right.packets_received;
    ret.packets_filtered = left.packets_filtered - right.packets_filtered;
    ret.packets_injected = left.packets_injected - right.packets_injected;

    for ( unsigned i = 0; i < MAX_DAQ_VERDICT; i++ )
        ret.verdicts[i] = left.verdicts[i] - right.verdicts[i];

    return ret;
}

void SFDAQModule::prep_counts()
{
    static THREAD_LOCAL DAQ_Stats_t sfdaq_stats;
    static THREAD_LOCAL PegCount last_skipped = 0;
    static THREAD_LOCAL bool did_init = false;

    if ( !did_init )
    {
        memset(&sfdaq_stats, 0, sizeof(DAQ_Stats_t));
        did_init = true;
    }

    if ( SFDAQ::get_local_instance() == nullptr )
        return;

    DAQ_Stats_t new_sfdaq_stats = *SFDAQ::get_stats();

    // must subtract explicitly; can't zero; daq stats are cumulative ...
    DAQ_Stats_t sfdaq_stats_delta = new_sfdaq_stats - sfdaq_stats;

    uint64_t pkts_out = new_sfdaq_stats.hw_packets_received -
                        new_sfdaq_stats.packets_filtered -
                        new_sfdaq_stats.packets_received;

    stats.pcaps = Trough::get_file_count();
    stats.received = sfdaq_stats_delta.hw_packets_received;
    stats.analyzed = sfdaq_stats_delta.packets_received;
    stats.dropped = sfdaq_stats_delta.hw_packets_dropped;
    stats.filtered =  sfdaq_stats_delta.packets_filtered;
    stats.outstanding =  pkts_out;
    stats.injected =  sfdaq_stats_delta.packets_injected;

    for ( unsigned i = 0; i < MAX_DAQ_VERDICT; i++ )
        stats.verdicts[i] = sfdaq_stats_delta.verdicts[i];

    stats.internal_blacklist = aux_counts.internal_blacklist;
    stats.internal_whitelist = aux_counts.internal_whitelist;
    stats.skipped = SnortConfig::get_conf()->pkt_skip - last_skipped;
    stats.idle = aux_counts.idle;
    stats.rx_bytes = aux_counts.rx_bytes;

    memset(&aux_counts, 0, sizeof(AuxCount));
    last_skipped = stats.skipped;

    sfdaq_stats = new_sfdaq_stats;
    for ( unsigned i = 0; i < MAX_DAQ_VERDICT; i++ )
        sfdaq_stats.verdicts[i] = new_sfdaq_stats.verdicts[i];
}

