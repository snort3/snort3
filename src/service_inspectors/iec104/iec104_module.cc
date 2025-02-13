//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// iec104_module.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_module.c (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_module.c (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iec104_module.h"

#include "profiler/profiler.h"
#include "trace/trace.h"

#include "iec104.h"
#include "iec104_trace.h"

using namespace snort;

THREAD_LOCAL ProfileStats iec104_prof;

THREAD_LOCAL const Trace* iec104_trace = nullptr;

#ifdef DEBUG_MSGS
static const TraceOption iec104_trace_options[] =
{
    { "identification", TRACE_IEC104_IDENTIFICATION, "enable IEC104 APDU identification trace logging" },

    { nullptr, 0, nullptr }
};
#endif

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions", "total sessions processed" },
    { CountType::SUM, "frames", "total IEC104 messages" },
    { CountType::NOW, "concurrent_sessions", "total concurrent IEC104 sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent IEC104 sessions" },

    { CountType::END, nullptr, nullptr }
};

const PegInfo* Iec104Module::get_pegs() const
{
    return peg_names;
}

PegCount* Iec104Module::get_counts() const
{
    return (PegCount*) &iec104_stats;
}

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------

static const RuleMap Iec104_rules[] =
{
    { IEC104_BAD_LENGTH, IEC104_BAD_LENGTH_STR },
    { IEC104_BAD_START, IEC104_BAD_START_STR },
    { IEC104_RESERVED_ASDU_TYPE, IEC104_RESERVED_ASDU_TYPE_STR },
    { IEC104_APCIU_RESERVED_FIELD_IN_USE, IEC104_APCIU_RESERVED_FIELD_IN_USE_STR },
    { IEC104_APCIU_INVALID_MESSAGE_TYPE, IEC104_APCIU_INVALID_MESSAGE_TYPE_STR },
    { IEC104_APCIS_RESERVED_FIELD_IN_USE, IEC104_APCIS_RESERVED_FIELD_IN_USE_STR },
    { IEC104_APCII_NUM_ELEMENTS_SET_TO_ZERO, IEC104_APCII_NUM_ELEMENTS_SET_TO_ZERO_STR },
    { IEC104_APCII_INVALID_SQ_VALUE, IEC104_APCII_INVALID_SQ_VALUE_STR },
    { IEC104_APCII_INVALID_NUM_ELEMENTS_VALUE, IEC104_APCII_INVALID_NUM_ELEMENTS_VALUE_STR },
    { IEC104_RESERVED_COI, IEC104_RESERVED_COI_STR },
    { IEC104_RESERVED_QOI, IEC104_RESERVED_QOI_STR },
    { IEC104_RESERVED_QCC, IEC104_RESERVED_QCC_STR },
    { IEC104_RESERVED_QPM_KPA, IEC104_RESERVED_QPM_KPA_STR },
    { IEC104_ABNORMAL_QPM_LPC, IEC104_ABNORMAL_QPM_LPC_STR },
    { IEC104_ABNORMAL_QPM_POP, IEC104_ABNORMAL_QPM_POP_STR },
    { IEC104_RESERVED_QPA, IEC104_RESERVED_QPA_STR },
    { IEC104_RESERVED_QOC, IEC104_RESERVED_QOC_STR },
    { IEC104_RESERVED_QRP, IEC104_RESERVED_QRP_STR },
    { IEC104_RESERVED_FRQ, IEC104_RESERVED_FRQ_STR },
    { IEC104_RESERVED_SRQ, IEC104_RESERVED_SRQ_STR },
    { IEC104_RESERVED_SCQ, IEC104_RESERVED_SCQ_STR },
    { IEC104_RESERVED_LSQ, IEC104_RESERVED_LSQ_STR },
    { IEC104_RESERVED_AFQ, IEC104_RESERVED_AFQ_STR },
    { IEC104_VSQ_ABNORMAL_SQ, IEC104_VSQ_ABNORMAL_SQ_STR },
    { IEC104_RESERVED_CAUSE_TX, IEC104_RESERVED_CAUSE_TX_STR },
    { IEC104_INVALID_CAUSE_TX, IEC104_INVALID_CAUSE_TX_STR },
    { IEC104_INVALID_COMMON_ADDRESS, IEC104_INVALID_COMMON_ADDRESS_STR },
    { IEC104_RESERVED_SIQ, IEC104_RESERVED_SIQ_STR },
    { IEC104_RESERVED_DIQ, IEC104_RESERVED_DIQ_STR },
    { IEC104_RESERVED_QDS, IEC104_RESERVED_QDS_STR },
    { IEC104_RESERVED_QDP, IEC104_RESERVED_QDP_STR },
    { IEC104_RESERVED_IEEE_STD_754_NAN, IEC104_RESERVED_IEEE_STD_754_NAN_STR },
    { IEC104_RESERVED_IEEE_STD_754_INFINITY, IEC104_RESERVED_IEEE_STD_754_INFINITY_STR },
    { IEC104_RESERVED_SEP, IEC104_RESERVED_SEP_STR },
    { IEC104_RESERVED_SPE, IEC104_RESERVED_SPE_STR },
    { IEC104_RESERVED_OCI, IEC104_RESERVED_OCI_STR },
    { IEC104_INVALID_FBP, IEC104_INVALID_FBP_STR },
    { IEC104_RESERVED_SCO, IEC104_RESERVED_SCO_STR },
    { IEC104_INVALID_DCO, IEC104_INVALID_DCO_STR },
    { IEC104_RESERVED_RCO, IEC104_RESERVED_RCO_STR },
    { IEC104_INVALID_MS_IN_MINUTE, IEC104_INVALID_MS_IN_MINUTE_STR },
    { IEC104_INVALID_MINS_IN_HOUR, IEC104_INVALID_MINS_IN_HOUR_STR },
    { IEC104_RESERVED_MINS_IN_HOUR, IEC104_RESERVED_MINS_IN_HOUR_STR },
    { IEC104_INVALID_HOURS_IN_DAY, IEC104_INVALID_HOURS_IN_DAY_STR },
    { IEC104_RESERVED_HOURS_IN_DAY, IEC104_RESERVED_HOURS_IN_DAY_STR },
    { IEC104_INVALID_DAY_OF_MONTH, IEC104_INVALID_DAY_OF_MONTH_STR },
    { IEC104_INVALID_MONTH, IEC104_INVALID_MONTH_STR },
    { IEC104_RESERVED_MONTH, IEC104_RESERVED_MONTH_STR },
    { IEC104_INVALID_YEAR, IEC104_INVALID_YEAR_STR },
    { IEC104_NULL_LOS_VALUE, IEC104_NULL_LOS_VALUE_STR },
    { IEC104_INVALID_LOS_VALUE, IEC104_INVALID_LOS_VALUE_STR },
    { IEC104_RESERVED_YEAR, IEC104_RESERVED_YEAR_STR },
    { IEC104_RESERVED_SOF, IEC104_RESERVED_SOF_STR },
    { IEC104_RESERVED_QOS, IEC104_RESERVED_QOS_STR },

    { 0, nullptr }
};

void Iec104Module::set_trace(const Trace* trace) const
{ iec104_trace = trace; }

const TraceOption* Iec104Module::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    return iec104_trace_options;
#endif
}

const RuleMap* Iec104Module::get_rules() const
{
    return Iec104_rules;
}

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

Iec104Module::Iec104Module() :
    Module(IEC104_NAME, IEC104_HELP)
{
}
