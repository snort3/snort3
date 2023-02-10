//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// iec104_module.h author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_module.h (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_module.h (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifndef IEC104_MODULE_H
#define IEC104_MODULE_H

#include "framework/module.h"

#define GID_IEC104 151

#define IEC104_NAME "iec104"
#define IEC104_HELP "iec104 inspection"

extern THREAD_LOCAL snort::ProfileStats iec104_prof;

class Iec104Module: public snort::Module
{
public:
    Iec104Module();

    unsigned get_gid() const override
    {
        return GID_IEC104;
    }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    {
        return &iec104_prof;
    }

    Usage get_usage() const override
    {
        return INSPECT;
    }

    bool is_bindable() const override
    {
        return true;
    }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;
};

#define IEC104_BAD_LENGTH 1
#define IEC104_BAD_START 2
#define IEC104_RESERVED_ASDU_TYPE 3
#define IEC104_APCIU_RESERVED_FIELD_IN_USE 4
#define IEC104_APCIU_INVALID_MESSAGE_TYPE 5
#define IEC104_APCIS_RESERVED_FIELD_IN_USE 6
#define IEC104_APCII_NUM_ELEMENTS_SET_TO_ZERO 7
#define IEC104_APCII_INVALID_SQ_VALUE 8
#define IEC104_APCII_INVALID_NUM_ELEMENTS_VALUE 9
#define IEC104_RESERVED_COI 10
#define IEC104_RESERVED_QOI 11
#define IEC104_RESERVED_QCC 12
#define IEC104_RESERVED_QPM_KPA 13
#define IEC104_ABNORMAL_QPM_LPC 14
#define IEC104_ABNORMAL_QPM_POP 15
#define IEC104_RESERVED_QPA 16
#define IEC104_RESERVED_QOC 17
#define IEC104_RESERVED_QRP 18
#define IEC104_RESERVED_FRQ 19
#define IEC104_RESERVED_SRQ 20
#define IEC104_RESERVED_SCQ 21
#define IEC104_RESERVED_LSQ 22
#define IEC104_RESERVED_AFQ 23
#define IEC104_VSQ_ABNORMAL_SQ 24
#define IEC104_RESERVED_SIQ 25
#define IEC104_RESERVED_DIQ 26
#define IEC104_RESERVED_CAUSE_TX 27
#define IEC104_INVALID_CAUSE_TX 28
#define IEC104_INVALID_COMMON_ADDRESS 29
#define IEC104_RESERVED_QDS 30
#define IEC104_RESERVED_QDP 31
#define IEC104_RESERVED_IEEE_STD_754_NAN 32
#define IEC104_RESERVED_IEEE_STD_754_INFINITY 33
#define IEC104_RESERVED_SEP 34
#define IEC104_RESERVED_SPE 35
#define IEC104_RESERVED_OCI 36
#define IEC104_INVALID_FBP 37
#define IEC104_RESERVED_SCO 38
#define IEC104_INVALID_DCO 39
#define IEC104_RESERVED_RCO 40
#define IEC104_INVALID_MS_IN_MINUTE 41
#define IEC104_INVALID_MINS_IN_HOUR 42
#define IEC104_RESERVED_MINS_IN_HOUR 43
#define IEC104_INVALID_HOURS_IN_DAY 44
#define IEC104_RESERVED_HOURS_IN_DAY 45
#define IEC104_INVALID_DAY_OF_MONTH 46
#define IEC104_INVALID_MONTH 47
#define IEC104_RESERVED_MONTH 48
#define IEC104_INVALID_YEAR 49
#define IEC104_RESERVED_YEAR 50
#define IEC104_NULL_LOS_VALUE 51
#define IEC104_INVALID_LOS_VALUE 52
#define IEC104_RESERVED_SOF 53
#define IEC104_RESERVED_QOS 54

#define IEC104_BAD_LENGTH_STR "Length in IEC104 APCI header does not match the length needed for the given IEC104 ASDU type id"
#define IEC104_BAD_START_STR "IEC104 Start byte does not match 0x68"
#define IEC104_RESERVED_ASDU_TYPE_STR "Reserved IEC104 ASDU type id in use"
#define IEC104_APCIU_RESERVED_FIELD_IN_USE_STR "IEC104 APCI U Reserved field contains a non-default value"
#define IEC104_APCIU_INVALID_MESSAGE_TYPE_STR "IEC104 APCI U message type was set to an invalid value"
#define IEC104_APCIS_RESERVED_FIELD_IN_USE_STR "IEC104 APCI S Reserved field contains a non-default value"
#define IEC104_APCII_NUM_ELEMENTS_SET_TO_ZERO_STR "IEC104 APCI I number of elements set to zero"
#define IEC104_APCII_INVALID_SQ_VALUE_STR "IEC104 APCI I SQ bit set on an ASDU that does not support the feature"
#define IEC104_APCII_INVALID_NUM_ELEMENTS_VALUE_STR "IEC104 APCI I number of elements set to greater than one on an ASDU that does not support the feature"
#define IEC104_RESERVED_COI_STR "IEC104 APCI I Cause of Initialization set to a reserved value"
#define IEC104_RESERVED_QOI_STR "IEC104 APCI I Qualifier of Interrogation Command set to a reserved value"
#define IEC104_RESERVED_QCC_STR "IEC104 APCI I Qualifier of Counter Interrogation Command request parameter set to a reserved value"
#define IEC104_RESERVED_QPM_KPA_STR "IEC104 APCI I Qualifier of Parameter of Measured Values kind of parameter set to a reserved value"
#define IEC104_ABNORMAL_QPM_LPC_STR "IEC104 APCI I Qualifier of Parameter of Measured Values local parameter change set to a technically valid but unused value"
#define IEC104_ABNORMAL_QPM_POP_STR "IEC104 APCI I Qualifier of Parameter of Measured Values parameter option set to a technically valid but unused value"
#define IEC104_RESERVED_QPA_STR "IEC104 APCI I Qualifier of Parameter Activation set to a reserved value"
#define IEC104_RESERVED_QOC_STR "IEC104 APCI I Qualifier of Command set to a reserved value"
#define IEC104_RESERVED_QRP_STR "IEC104 APCI I Qualifier of Reset Process set to a reserved value"
#define IEC104_RESERVED_FRQ_STR "IEC104 APCI I File Ready Qualifier set to a reserved value"
#define IEC104_RESERVED_SRQ_STR "IEC104 APCI I Section Ready Qualifier set to a reserved value"
#define IEC104_RESERVED_SCQ_STR "IEC104 APCI I Select and Call Qualifier set to a reserved value"
#define IEC104_RESERVED_LSQ_STR "IEC104 APCI I Last Section or Segment Qualifier set to a reserved value"
#define IEC104_RESERVED_AFQ_STR "IEC104 APCI I Acknowledge File or Section Qualifier set to a reserved value"
#define IEC104_VSQ_ABNORMAL_SQ_STR "IEC104 APCI I Structure Qualifier set on a message where it should have no effect"
#define IEC104_RESERVED_CAUSE_TX_STR "IEC104 APCI I Cause of Transmission set to a reserved value"
#define IEC104_INVALID_CAUSE_TX_STR "IEC104 APCI I Cause of Transmission set to a value not allowed for the ASDU"
#define IEC104_INVALID_COMMON_ADDRESS_STR "IEC104 APCI I invalid two octet common address value detected"
#define IEC104_RESERVED_SIQ_STR "IEC104 APCI I Single Point Information Reserved field contains a non-default value"
#define IEC104_RESERVED_DIQ_STR "IEC104 APCI I Double Point Information Reserved field contains a non-default value"
#define IEC104_RESERVED_QDS_STR "IEC104 APCI I Quality Descriptor Structure Reserved field contains a non-default value"
#define IEC104_RESERVED_QDP_STR "IEC104 APCI I Quality Descriptor for Events of Protection Equipment Structure Reserved field contains a non-default value"
#define IEC104_RESERVED_IEEE_STD_754_NAN_STR "IEC104 APCI I IEEE STD 754 value results in NaN"
#define IEC104_RESERVED_IEEE_STD_754_INFINITY_STR "IEC104 APCI I IEEE STD 754 value results in infinity"
#define IEC104_RESERVED_SEP_STR "IEC104 APCI I Single Event of Protection Equipment Structure Reserved field contains a non-default value"
#define IEC104_RESERVED_SPE_STR "IEC104 APCI I Start Event of Protection Equipment Structure Reserved field contains a non-default value"
#define IEC104_RESERVED_OCI_STR "IEC104 APCI I Output Circuit Information Structure Reserved field contains a non-default value"
#define IEC104_INVALID_FBP_STR "IEC104 APCI I Abnormal Fixed Test Bit Pattern detected"
#define IEC104_RESERVED_SCO_STR "IEC104 APCI I Single Command Structure Reserved field contains a non-default value"
#define IEC104_INVALID_DCO_STR "IEC104 APCI I Double Command Structure contains an invalid value"
#define IEC104_RESERVED_RCO_STR "IEC104 APCI I Regulating Step Command Structure Reserved field contains a non-default value"
#define IEC104_INVALID_MS_IN_MINUTE_STR "IEC104 APCI I Time2a Millisecond set outside of the allowable range"
#define IEC104_INVALID_MINS_IN_HOUR_STR "IEC104 APCI I Time2a Minute set outside of the allowable range"
#define IEC104_RESERVED_MINS_IN_HOUR_STR "IEC104 APCI I Time2a Minute Reserved field contains a non-default value"
#define IEC104_INVALID_HOURS_IN_DAY_STR "IEC104 APCI I Time2a Hours set outside of the allowable range"
#define IEC104_RESERVED_HOURS_IN_DAY_STR "IEC104 APCI I Time2a Hours Reserved field contains a non-default value"
#define IEC104_INVALID_DAY_OF_MONTH_STR "IEC104 APCI I Time2a Day of Month set outside of the allowable range"
#define IEC104_INVALID_MONTH_STR "IEC104 APCI I Time2a Month set outside of the allowable range"
#define IEC104_RESERVED_MONTH_STR "IEC104 APCI I Time2a Month Reserved field contains a non-default value"
#define IEC104_INVALID_YEAR_STR "IEC104 APCI I Time2a Year set outside of the allowable range"
#define IEC104_NULL_LOS_VALUE_STR "IEC104 APCI I a null Length of Segment value has been detected"
#define IEC104_INVALID_LOS_VALUE_STR "IEC104 APCI I an invalid Length of Segment value has been detected"
#define IEC104_RESERVED_YEAR_STR "IEC104 APCI I Time2a Year Reserved field contains a non-default value"
#define IEC104_RESERVED_SOF_STR "IEC104 APCI I Status of File set to a reserved value"
#define IEC104_RESERVED_QOS_STR "IEC104 APCI I Qualifier of Set Point Command ql field set to a reserved value"

#endif

