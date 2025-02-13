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

// ips_iec104_asdu_func.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after ips_modbus_func.cc (author Russ Combs <rucombs@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "iec104.h"
#include "iec104_parse_apdu.h"

using namespace snort;

static const char* s_name = "iec104_asdu_func";

//-------------------------------------------------------------------------
// func lookup
//-------------------------------------------------------------------------

struct Iec104AsduFuncMap
{
    const char* name;
    uint8_t func;
};

/* Mapping of name -> function code for 'iec104_asdu_func' option. */
static Iec104AsduFuncMap iec104_asdu_func_map[] =
{
    { "reserved",  IEC104_NO_ASDU },                                                 // 0 reserved
    { "M_SP_NA_1", IEC104_ASDU_M_SP_NA_1 }, { "m_sp_na_1", IEC104_ASDU_M_SP_NA_1 }, // Single-point information
    { "M_SP_TA_1", IEC104_ASDU_M_SP_TA_1 }, { "m_sp_ta_1", IEC104_ASDU_M_SP_TA_1 }, // Single-point information with time tag
    { "M_DP_NA_1", IEC104_ASDU_M_DP_NA_1 }, { "m_dp_na_1", IEC104_ASDU_M_DP_NA_1 }, // Double-point information
    { "M_DP_TA_1", IEC104_ASDU_M_DP_TA_1 }, { "m_dp_ta_1", IEC104_ASDU_M_DP_TA_1 }, // Double-point information with time tag
    { "M_ST_NA_1", IEC104_ASDU_M_ST_NA_1 }, { "m_st_na_1", IEC104_ASDU_M_ST_NA_1 }, // Step position information
    { "M_ST_TA_1", IEC104_ASDU_M_ST_TA_1 }, { "m_st_ta_1", IEC104_ASDU_M_ST_TA_1 }, // Step position information with time tag
    { "M_BO_NA_1", IEC104_ASDU_M_BO_NA_1 }, { "m_bo_na_1", IEC104_ASDU_M_BO_NA_1 }, // Bitstring of 32 bit
    { "M_BO_TA_1", IEC104_ASDU_M_BO_TA_1 }, { "m_bo_ta_1", IEC104_ASDU_M_BO_TA_1 }, // Bitstring of 32 bit with time tag
    { "M_ME_NA_1", IEC104_ASDU_M_ME_NA_1 }, { "m_me_na_1", IEC104_ASDU_M_ME_NA_1 }, // Measured value, normalized value
    { "M_ME_TA_1", IEC104_ASDU_M_ME_TA_1 }, { "m_me_ta_1", IEC104_ASDU_M_ME_TA_1 }, // Measured value, normalized value with time tag
    { "M_ME_NB_1", IEC104_ASDU_M_ME_NB_1 }, { "m_me_nb_1", IEC104_ASDU_M_ME_NB_1 }, // Measured value, scaled value
    { "M_ME_TB_1", IEC104_ASDU_M_ME_TB_1 }, { "m_me_tb_1", IEC104_ASDU_M_ME_TB_1 }, // Measured value, scaled value wit time tag
    { "M_ME_NC_1", IEC104_ASDU_M_ME_NC_1 }, { "m_me_nc_1", IEC104_ASDU_M_ME_NC_1 }, // Measured value, short floating point number
    { "M_ME_TC_1", IEC104_ASDU_M_ME_TC_1 }, { "m_me_tc_1", IEC104_ASDU_M_ME_TC_1 }, // Measured value, short floating point number with time tag
    { "M_IT_NA_1", IEC104_ASDU_M_IT_NA_1 }, { "m_it_na_1", IEC104_ASDU_M_IT_NA_1 }, // Integrated totals
    { "M_IT_TA_1", IEC104_ASDU_M_IT_TA_1 }, { "m_it_ta_1", IEC104_ASDU_M_IT_TA_1 }, // Integrated totals with time tag
    { "M_EP_TA_1", IEC104_ASDU_M_EP_TA_1 }, { "m_ep_ta_1", IEC104_ASDU_M_EP_TA_1 }, // Event of protection equipment with time tag
    { "M_EP_TB_1", IEC104_ASDU_M_EP_TB_1 }, { "m_ep_tb_1", IEC104_ASDU_M_EP_TB_1 }, // Packed start events of protection equipment with time tag
    { "M_EP_TC_1", IEC104_ASDU_M_EP_TC_1 }, { "m_ep_tc_1", IEC104_ASDU_M_EP_TC_1 }, // Packed output circuit information of protection equipment with time tag
    { "M_PS_NA_1", IEC104_ASDU_M_PS_NA_1 }, { "m_ps_na_1", IEC104_ASDU_M_PS_NA_1 }, // Packed single point information with status change detection
    { "M_ME_ND_1", IEC104_ASDU_M_ME_ND_1 }, { "m_me_nd_1", IEC104_ASDU_M_ME_ND_1 }, // Measured value, normalized value without quality descriptor
    // 22-29 reserved
    { "M_SP_TB_1", IEC104_ASDU_M_SP_TB_1 }, { "m_sp_tb_1", IEC104_ASDU_M_SP_TB_1 }, // Single-point information with time tag CP56Time2a
    { "M_DP_TB_1", IEC104_ASDU_M_DP_TB_1 }, { "m_dp_tb_1", IEC104_ASDU_M_DP_TB_1 }, // Double-point information with time tag CP56Time2a
    { "M_ST_TB_1", IEC104_ASDU_M_ST_TB_1 }, { "m_st_tb_1", IEC104_ASDU_M_ST_TB_1 }, // Step position information with time tag CP56Time2a
    { "M_BO_TB_1", IEC104_ASDU_M_BO_TB_1 }, { "m_bo_tb_1", IEC104_ASDU_M_BO_TB_1 }, // Bitstring of 32 bit with time tag CP56Time2a
    { "M_ME_TD_1", IEC104_ASDU_M_ME_TD_1 }, { "m_me_td_1", IEC104_ASDU_M_ME_TD_1 }, // Measured value, normalized value with time tag CP56Time2a
    { "M_ME_TE_1", IEC104_ASDU_M_ME_TE_1 }, { "m_me_te_1", IEC104_ASDU_M_ME_TE_1 }, // Measured value, scaled value with time tag CP56Time2a
    { "M_ME_TF_1", IEC104_ASDU_M_ME_TF_1 }, { "m_me_tf_1", IEC104_ASDU_M_ME_TF_1 }, // Measured value, short floating point number with time tag CP56Time2a
    { "M_IT_TB_1", IEC104_ASDU_M_IT_TB_1 }, { "m_it_tb_1", IEC104_ASDU_M_IT_TB_1 }, // Integrated totals with time tag CP56Time2a
    { "M_EP_TD_1", IEC104_ASDU_M_EP_TD_1 }, { "m_ep_td_1", IEC104_ASDU_M_EP_TD_1 }, // Event of protection equipment with time tag CP56Time2a
    { "M_EP_TE_1", IEC104_ASDU_M_EP_TE_1 }, { "m_ep_te_1", IEC104_ASDU_M_EP_TE_1 }, // Packed start events of protection equipment with time tag CP56Time2a
    { "M_EP_TF_1", IEC104_ASDU_M_EP_TF_1 }, { "m_ep_tf_1", IEC104_ASDU_M_EP_TF_1 }, // Packed output circuit information of protection equipment with time tag CP56Time2a
    // 41-44 reserved
    { "C_SC_NA_1", IEC104_ASDU_C_SC_NA_1 }, { "c_sc_na_1", IEC104_ASDU_C_SC_NA_1 }, // Single command
    { "C_DC_NA_1", IEC104_ASDU_C_DC_NA_1 }, { "c_dc_na_1", IEC104_ASDU_C_DC_NA_1 }, // Double command
    { "C_RC_NA_1", IEC104_ASDU_C_RC_NA_1 }, { "c_rc_na_1", IEC104_ASDU_C_RC_NA_1 }, // Regulating step command
    { "C_SE_NA_1", IEC104_ASDU_C_SE_NA_1 }, { "c_se_na_1", IEC104_ASDU_C_SE_NA_1 }, // Set-point Command, normalized value
    { "C_SE_NB_1", IEC104_ASDU_C_SE_NB_1 }, { "c_se_nb_1", IEC104_ASDU_C_SE_NB_1 }, // Set-point Command, scaled value
    { "C_SE_NC_1", IEC104_ASDU_C_SE_NC_1 }, { "c_se_nc_1", IEC104_ASDU_C_SE_NC_1 }, // Set-point Command, short floating point number
    { "C_BO_NA_1", IEC104_ASDU_C_BO_NA_1 }, { "c_bo_na_1", IEC104_ASDU_C_BO_NA_1 }, // Bitstring 32 bit command
    // 52-57 reserved
    { "C_SC_TA_1", IEC104_ASDU_C_SC_TA_1 }, { "c_sc_ta_1", IEC104_ASDU_C_SC_TA_1 }, // Single command with time tag CP56Time2a
    { "C_DC_TA_1", IEC104_ASDU_C_DC_TA_1 }, { "c_dc_ta_1", IEC104_ASDU_C_DC_TA_1 }, // Double command with time tag CP56Time2a
    { "C_RC_TA_1", IEC104_ASDU_C_RC_TA_1 }, { "c_rc_ta_1", IEC104_ASDU_C_RC_TA_1 }, // Regulating step command with time tag CP56Time2a
    { "C_SE_TA_1", IEC104_ASDU_C_SE_TA_1 }, { "c_se_ta_1", IEC104_ASDU_C_SE_TA_1 }, // Set-point command with time tag CP56Time2a, normalized value
    { "C_SE_TB_1", IEC104_ASDU_C_SE_TB_1 }, { "c_se_tb_1", IEC104_ASDU_C_SE_TB_1 }, // Set-point command with time tag CP56Time2a, scaled value
    { "C_SE_TC_1", IEC104_ASDU_C_SE_TC_1 }, { "c_se_tc_1", IEC104_ASDU_C_SE_TC_1 }, // Set-point command with time tag CP56Time2a, short floating point number
    { "C_BO_TA_1", IEC104_ASDU_C_BO_TA_1 }, { "c_bo_ta_1", IEC104_ASDU_C_BO_TA_1 }, // Bitstring of 32 bit with time tag CP56Time2a
    // 65-69 reserved
    { "M_EI_NA_1", IEC104_ASDU_M_EI_NA_1 }, { "m_ei_na_1", IEC104_ASDU_M_EI_NA_1 }, // End of initialization
    // 71-99 reserved
    { "C_IC_NA_1", IEC104_ASDU_C_IC_NA_1 }, { "c_ic_na_1", IEC104_ASDU_C_IC_NA_1 }, // Interrogation command
    { "C_CI_NA_1", IEC104_ASDU_C_CI_NA_1 }, { "c_ci_na_1", IEC104_ASDU_C_CI_NA_1 }, // Counter interrogation command
    { "C_RD_NA_1", IEC104_ASDU_C_RD_NA_1 }, { "c_rd_na_1", IEC104_ASDU_C_RD_NA_1 }, // Read command
    { "C_CS_NA_1", IEC104_ASDU_C_CS_NA_1 }, { "c_cs_na_1", IEC104_ASDU_C_CS_NA_1 }, // Clock synchronization command
    { "C_TS_NA_1", IEC104_ASDU_C_TS_NA_1 }, { "c_ts_na_1", IEC104_ASDU_C_TS_NA_1 }, // Test command
    { "C_RP_NA_1", IEC104_ASDU_C_RP_NA_1 }, { "c_rp_na_1", IEC104_ASDU_C_RP_NA_1 }, // Reset process command
    { "C_CD_NA_1", IEC104_ASDU_C_CD_NA_1 }, { "c_cd_na_1", IEC104_ASDU_C_CD_NA_1 }, // Delay acquisition command
    { "C_TS_TA_1", IEC104_ASDU_C_TS_TA_1 }, { "c_ts_ta_1", IEC104_ASDU_C_TS_TA_1 }, // Test command with time tag CP56Time2a
    // 108-109 reserved
    { "P_ME_NA_1", IEC104_ASDU_P_ME_NA_1 }, { "p_me_na_1", IEC104_ASDU_P_ME_NA_1 }, // Parameter of measured values, normalized value
    { "P_ME_NB_1", IEC104_ASDU_P_ME_NB_1 }, { "p_me_nb_1", IEC104_ASDU_P_ME_NB_1 }, // Parameter of measured values, scaled value
    { "P_ME_NC_1", IEC104_ASDU_P_ME_NC_1 }, { "p_me_nc_1", IEC104_ASDU_P_ME_NC_1 }, // Parameter of measured values, short floating point number
    { "P_AC_NA_1", IEC104_ASDU_P_AC_NA_1 }, { "p_ac_na_1", IEC104_ASDU_P_AC_NA_1 }, // Parameter activation
    // 114-119 reserved
    { "F_FR_NA_1", IEC104_ASDU_F_FR_NA_1 }, { "f_fr_na_1", IEC104_ASDU_F_FR_NA_1 }, // File ready
    { "F_SR_NA_1", IEC104_ASDU_F_SR_NA_1 }, { "f_sr_na_1", IEC104_ASDU_F_SR_NA_1 }, // Section ready
    { "F_SC_NA_1", IEC104_ASDU_F_SC_NA_1 }, { "f_sc_na_1", IEC104_ASDU_F_SC_NA_1 }, // Call directory, select file, call file, call section
    { "F_LS_NA_1", IEC104_ASDU_F_LS_NA_1 }, { "f_ls_na_1", IEC104_ASDU_F_LS_NA_1 }, // Last section, last segment
    { "F_AF_NA_1", IEC104_ASDU_F_AF_NA_1 }, { "f_af_na_1", IEC104_ASDU_F_AF_NA_1 }, // ACK file, ACK section
    { "F_SG_NA_1", IEC104_ASDU_F_SG_NA_1 }, { "f_sg_na_1", IEC104_ASDU_F_SG_NA_1 }, // Single information object
    { "F_DR_TA_1", IEC104_ASDU_F_DR_TA_1 }, { "f_dr_ta_1", IEC104_ASDU_F_DR_TA_1 }, // Sequence of information elements in a single information object
    { "F_SC_NB_1", IEC104_ASDU_F_SC_NB_1 }, { "f_sc_nb_1", IEC104_ASDU_F_SC_NB_1 }, // QueryLog – Request archive file
    // 128-256 reserved
    };

static bool get_func(const char* s, long& n)
{
    constexpr size_t max = (sizeof(iec104_asdu_func_map) / sizeof(Iec104AsduFuncMap));

    for (size_t i = 0; i < max; ++i)
    {
        if (!strcmp(s, iec104_asdu_func_map[i].name))
        {
            n = iec104_asdu_func_map[i].func;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// func option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats iec104_asdu_func_prof;

class Iec104AsduFuncOption: public IpsOption
{
public:
    Iec104AsduFuncOption(uint16_t v) :
        IpsOption(s_name)
    {
        func = v;
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint16_t func;
};

uint32_t Iec104AsduFuncOption::hash() const
{
    uint32_t a = func, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool Iec104AsduFuncOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
    {
        return false;
    }

    const Iec104AsduFuncOption& rhs = (const Iec104AsduFuncOption&) ips;
    return (func == rhs.func);
}

IpsOption::EvalStatus Iec104AsduFuncOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(iec104_asdu_func_prof);

    if (!p->flow)
    {
        return NO_MATCH;
    }

    if (!p->is_full_pdu())
    {
        return NO_MATCH;
    }

    // check if the packet function matches the rule option function
    Iec104FlowData* iec104fd = (Iec104FlowData*) p->flow->get_flow_data(Iec104FlowData::inspector_id);

    // ASDU only occurs in APCI type I
    if (iec104fd and iec104fd->ssn_data.iec104_apci_type == IEC104_APCI_TYPE_I)
    {
        // alert only when the target function matches the existing function
        if (func == iec104fd->ssn_data.iec104_asdu_func)
        {
            return MATCH;
        }
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "function code to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check iec104 function code"

class Iec104AsduFuncModule: public Module
{
public:
    Iec104AsduFuncModule() :
        Module(s_name, s_help, s_params)
    {
    }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &iec104_asdu_func_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    uint8_t func = IEC104_NO_ASDU;
};

bool Iec104AsduFuncModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if (v.strtol(n))
        func = static_cast<uint8_t>(n);

    else if (get_func(v.get_string(), n))
        func = static_cast<uint8_t>(n);

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Iec104AsduFuncModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    Iec104AsduFuncModule* mod = (Iec104AsduFuncModule*) m;
    return new Iec104AsduFuncOption(mod->func);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0,
    PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_iec104_asdu_func = &ips_api.base;

