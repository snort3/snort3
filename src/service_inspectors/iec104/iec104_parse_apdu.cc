//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// iec104_parse_apdu.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iec104_parse_apdu.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

#include "iec104.h"
#include "iec104_decode.h"
#include "iec104_module.h"
#include "iec104_parse_information_object_elements.h"

using namespace snort;

// perform some checks on the ASDU
static bool checkIec104Asdu(Iec104AsduCheck curAsduCheck)
{
    // keep a flag to indicate whether we should exit after executing
    // taking this approach instead of returning directly as multiple of these
    //   cases could exist and we want to alert on all of them
    bool continueProcessing = true;

    // make sure the number of elements is not zero
    if (curAsduCheck.apci->asdu.variableStructureQualifier.numberOfElements == 0)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_APCII_NUM_ELEMENTS_SET_TO_ZERO);

        // indicate that we should stop parsing after the return of this function
        continueProcessing = false;
    }

    // When indicated, the ASDU should not have a SQ value of 0
    // this is not the case for most asdus
    if (!curAsduCheck.sq0Allowed)
    {
        if (curAsduCheck.apci->asdu.variableStructureQualifier.sq != IEC104_SQ_TRUE)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_APCII_INVALID_SQ_VALUE);

            // indicate that we should stop parsing after the return of this function
            continueProcessing = false;
        }
    }

    // When indicated, the ASDU should not have a SQ value of 1
    // this is not the case for most asdus
    if (!curAsduCheck.sq1Allowed)
    {
        if (curAsduCheck.apci->asdu.variableStructureQualifier.sq != IEC104_SQ_FALSE)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_APCII_INVALID_SQ_VALUE);

            // indicate that we should stop parsing after the return of this function
            continueProcessing = false;
        }
    }

    // When indicated, the ASDU should not have a number of items greater than 1
    // this is not the case for most asdus
    if (!curAsduCheck.multipleIOAllowed)
    {
        if (curAsduCheck.apci->asdu.variableStructureQualifier.numberOfElements > 1)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_APCII_INVALID_NUM_ELEMENTS_VALUE);

            // indicate that we should stop parsing after the return of this function
            continueProcessing = false;
        }
    }

    // Verify that the cause of transmission indicated by the sender is one that is
    // allowed for the message type
    switch (curAsduCheck.apci->asdu.causeOfTransmission.causeOfTransmission)
    {
    case IEC104_CAUSE_TX_PER_CYC:
    {
        if (!curAsduCheck.checkCauseOfTx.percyc)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_BACK:
    {
        if (!curAsduCheck.checkCauseOfTx.back)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_SPONT:
    {
        if (!curAsduCheck.checkCauseOfTx.spont)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INIT:
    {
        if (!curAsduCheck.checkCauseOfTx.init)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_REQ:
    {
        if (!curAsduCheck.checkCauseOfTx.req)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_ACT:
    {
        if (!curAsduCheck.checkCauseOfTx.act)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_ACTCON:
    {
        if (!curAsduCheck.checkCauseOfTx.actcon)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_DEACT:
    {
        if (!curAsduCheck.checkCauseOfTx.deact)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_DEACTCON:
    {
        if (!curAsduCheck.checkCauseOfTx.deactcon)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_ACTTERM:
    {
        if (!curAsduCheck.checkCauseOfTx.actterm)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_RETREM:
    {
        if (!curAsduCheck.checkCauseOfTx.retrem)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_RETLOC:
    {
        if (!curAsduCheck.checkCauseOfTx.retloc)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_FILE:
    {
        if (!curAsduCheck.checkCauseOfTx.file)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INROGEN:
    {
        if (!curAsduCheck.checkCauseOfTx.inrogen)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO1:
    {
        if (!curAsduCheck.checkCauseOfTx.inro1)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO2:
    {
        if (!curAsduCheck.checkCauseOfTx.inro2)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO3:
    {
        if (!curAsduCheck.checkCauseOfTx.inro3)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO4:
    {
        if (!curAsduCheck.checkCauseOfTx.inro4)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO5:
    {
        if (!curAsduCheck.checkCauseOfTx.inro5)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO6:
    {
        if (!curAsduCheck.checkCauseOfTx.inro6)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO7:
    {
        if (!curAsduCheck.checkCauseOfTx.inro7)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO8:
    {
        if (!curAsduCheck.checkCauseOfTx.inro8)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO9:
    {
        if (!curAsduCheck.checkCauseOfTx.inro9)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO10:
    {
        if (!curAsduCheck.checkCauseOfTx.inro10)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO11:
    {
        if (!curAsduCheck.checkCauseOfTx.inro11)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO12:
    {
        if (!curAsduCheck.checkCauseOfTx.inro12)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO13:
    {
        if (!curAsduCheck.checkCauseOfTx.inro13)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO14:
    {
        if (!curAsduCheck.checkCauseOfTx.inro14)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO15:
    {
        if (!curAsduCheck.checkCauseOfTx.inro15)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_INRO16:
    {
        if (!curAsduCheck.checkCauseOfTx.inro16)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_REQCOGEN:
    {
        if (!curAsduCheck.checkCauseOfTx.reqcogen)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_REQCO1:
    {
        if (!curAsduCheck.checkCauseOfTx.reqco1)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_REQCO2:
    {
        if (!curAsduCheck.checkCauseOfTx.reqco2)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_REQCO3:
    {
        if (!curAsduCheck.checkCauseOfTx.reqco3)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_REQCO4:
    {
        if (!curAsduCheck.checkCauseOfTx.reqco4)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_UNKNOWN_TYPE_ID:
    {
        if (!curAsduCheck.checkCauseOfTx.unk_type_id)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_UNKNOWN_CAUSE_OF_TX:
    {
        if (!curAsduCheck.checkCauseOfTx.unk_cause_tx)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_UNKNOWN_COMMON_ADDR_OF_ASDU:
    {
        if (!curAsduCheck.checkCauseOfTx.unk_common_addr)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_UNKNOWN_IOA:
    {
        if (!curAsduCheck.checkCauseOfTx.unk_info_addr)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_CAUSE_TX);
        }
        break;
    }

    case IEC104_CAUSE_TX_RES14: // 14-19 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES15: // 14-19 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES16: // 14-19 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES17: // 14-19 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES18: // 14-19 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES19: // 14-19 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES42: // 42-43 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES43: // 42-43 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES48: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES49: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES50: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES51: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES52: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES53: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES54: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES55: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES56: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES57: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES58: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES59: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES60: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES61: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES62: // 48-63 reserved. falls through into other reserved processing
    case IEC104_CAUSE_TX_RES63: // 48-63 reserved
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_CAUSE_TX);
        break;
    }

    default:
    {
        // Invalid Cause of Transmission
    }
    }

    return continueProcessing;
}

// Function to perform the desired parsing based off of the ASDU type
// This should not be called directly by anything other than parseGenericAsdu
static void parseIec104GenericIOGroup(const GenericIec104AsduIOGroup* genericIOGroup)
{
    // determine which ASDU parsing logic to run based off of the passed type
    switch (genericIOGroup->asduType)
    {
    case IEC104_ASDU_M_SP_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_sp_na_1IOGroup->ioa);
        }
        parseIec104Siq(&genericIOGroup->m_sp_na_1IOSubgroup->siq);
        break;
    }

    case IEC104_ASDU_M_SP_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_sp_ta_1IOGroup->ioa);
        }
        parseIec104Siq(&genericIOGroup->m_sp_ta_1IOSubgroup->siq);
        parseIec104Cp24Time2a(&genericIOGroup->m_sp_ta_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_DP_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_dp_na_1IOGroup->ioa);
        }
        parseIec104Diq(&genericIOGroup->m_dp_na_1IOSubgroup->diq);
        break;
    }

    case IEC104_ASDU_M_DP_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_dp_ta_1IOGroup->ioa);
        }
        parseIec104Diq(&genericIOGroup->m_dp_ta_1IOSubgroup->diq);
        parseIec104Cp24Time2a(&genericIOGroup->m_dp_ta_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ST_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_st_na_1IOGroup->ioa);
        }
        parseIec104Vti(&genericIOGroup->m_st_na_1IOSubgroup->vti);
        parseIec104Qds(&genericIOGroup->m_st_na_1IOSubgroup->qds);
        break;
    }

    case IEC104_ASDU_M_ST_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_st_ta_1IOGroup->ioa);
        }
        parseIec104Vti(&genericIOGroup->m_st_ta_1IOSubgroup->vti);
        parseIec104Qds(&genericIOGroup->m_st_ta_1IOSubgroup->qds);
        parseIec104Cp24Time2a(&genericIOGroup->m_st_ta_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_BO_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_bo_na_1IOGroup->ioa);
        }
        parseIec104Bsi(&genericIOGroup->m_bo_na_1IOSubgroup->bsi);
        parseIec104Qds(&genericIOGroup->m_bo_na_1IOSubgroup->qds);
        break;
    }

    case IEC104_ASDU_M_BO_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_bo_ta_1IOGroup->ioa);
        }
        parseIec104Bsi(&genericIOGroup->m_bo_ta_1IOSubgroup->bsi);
        parseIec104Qds(&genericIOGroup->m_bo_ta_1IOSubgroup->qds);
        parseIec104Cp24Time2a(&genericIOGroup->m_bo_ta_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ME_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_na_1IOGroup->ioa);
        }
        parseIec104Nva(&genericIOGroup->m_me_na_1IOSubgroup->nva);
        parseIec104Qds(&genericIOGroup->m_me_na_1IOSubgroup->qds);
        break;
    }

    case IEC104_ASDU_M_ME_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_ta_1IOGroup->ioa);
        }
        parseIec104Nva(&genericIOGroup->m_me_ta_1IOSubgroup->nva);
        parseIec104Qds(&genericIOGroup->m_me_ta_1IOSubgroup->qds);
        parseIec104Cp24Time2a(&genericIOGroup->m_me_ta_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ME_NB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_nb_1IOGroup->ioa);
        }
        parseIec104Sva(&genericIOGroup->m_me_nb_1IOSubgroup->sva);
        parseIec104Qds(&genericIOGroup->m_me_nb_1IOSubgroup->qds);
        break;
    }

    case IEC104_ASDU_M_ME_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_tb_1IOGroup->ioa);
        }
        parseIec104Sva(&genericIOGroup->m_me_tb_1IOSubgroup->sva);
        parseIec104Qds(&genericIOGroup->m_me_tb_1IOSubgroup->qds);
        parseIec104Cp24Time2a(&genericIOGroup->m_me_tb_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ME_NC_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_nc_1IOGroup->ioa);
        }
        parseIec104IeeeStd754(&genericIOGroup->m_me_nc_1IOSubgroup->ieeeStd754);
        parseIec104Qds(&genericIOGroup->m_me_nc_1IOSubgroup->qds);
        break;
    }

    case IEC104_ASDU_M_ME_TC_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_tc_1IOGroup->ioa);
        }
        parseIec104IeeeStd754(&genericIOGroup->m_me_tc_1IOSubgroup->ieeeStd754);
        parseIec104Qds(&genericIOGroup->m_me_tc_1IOSubgroup->qds);
        parseIec104Cp24Time2a(&genericIOGroup->m_me_tc_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_IT_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_it_na_1IOGroup->ioa);
        }
        parseIec104Bcr(&genericIOGroup->m_it_na_1IOSubgroup->bcr);
        break;
    }

    case IEC104_ASDU_M_IT_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_it_ta_1IOGroup->ioa);
        }
        parseIec104Bcr(&genericIOGroup->m_it_ta_1IOSubgroup->bcr);
        parseIec104Cp24Time2a(&genericIOGroup->m_it_ta_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_EP_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ep_ta_1IOGroup->ioa);
        }
        parseIec104Sep(&genericIOGroup->m_ep_ta_1IOSubgroup->sep);
        parseIec104Cp16Time2a(&genericIOGroup->m_ep_ta_1IOSubgroup->elapsedTime);
        parseIec104Cp24Time2a(&genericIOGroup->m_ep_ta_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_EP_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ep_tb_1IOGroup->ioa);
        }
        parseIec104Spe(&genericIOGroup->m_ep_tb_1IOSubgroup->spe);
        parseIec104Qdp(&genericIOGroup->m_ep_tb_1IOSubgroup->qdp);
        parseIec104Cp16Time2a(&genericIOGroup->m_ep_tb_1IOSubgroup->relayDurationTime);
        parseIec104Cp24Time2a(&genericIOGroup->m_ep_tb_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_EP_TC_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ep_tc_1IOGroup->ioa);
        }
        parseIec104Oci(&genericIOGroup->m_ep_tc_1IOSubgroup->oci);
        parseIec104Qdp(&genericIOGroup->m_ep_tc_1IOSubgroup->qdp);
        parseIec104Cp16Time2a(&genericIOGroup->m_ep_tc_1IOSubgroup->relayOperatingTime);
        parseIec104Cp24Time2a(&genericIOGroup->m_ep_tc_1IOSubgroup->threeOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_PS_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ps_na_1IOGroup->ioa);
        }
        parseIec104Scd(&genericIOGroup->m_ps_na_1IOSubgroup->scd);
        parseIec104Qds(&genericIOGroup->m_ps_na_1IOSubgroup->qds);
        break;
    }

    case IEC104_ASDU_M_ME_ND_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_nd_1IOGroup->ioa);
        }
        parseIec104Nva(&genericIOGroup->m_me_nd_1IOSubgroup->nva);
        break;
    }

    case IEC104_ASDU_M_SP_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_sp_tb_1IOGroup->ioa);
        }
        parseIec104Siq(&genericIOGroup->m_sp_tb_1IOSubgroup->siq);
        parseIec104Cp56Time2a(&genericIOGroup->m_sp_tb_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_DP_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_dp_tb_1IOGroup->ioa);
        }
        parseIec104Diq(&genericIOGroup->m_dp_tb_1IOSubgroup->diq);
        parseIec104Cp56Time2a(&genericIOGroup->m_dp_tb_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ST_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_st_tb_1IOGroup->ioa);
        }
        parseIec104Vti(&genericIOGroup->m_st_tb_1IOSubgroup->vti);
        parseIec104Qds(&genericIOGroup->m_st_tb_1IOSubgroup->qds);
        parseIec104Cp56Time2a(&genericIOGroup->m_st_tb_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_BO_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_bo_tb_1IOGroup->ioa);
        }
        parseIec104Bsi(&genericIOGroup->m_bo_tb_1IOSubgroup->bsi);
        parseIec104Qds(&genericIOGroup->m_bo_tb_1IOSubgroup->qds);
        parseIec104Cp56Time2a(&genericIOGroup->m_bo_tb_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ME_TD_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_td_1IOGroup->ioa);
        }
        parseIec104Nva(&genericIOGroup->m_me_td_1IOSubgroup->nva);
        parseIec104Qds(&genericIOGroup->m_me_td_1IOSubgroup->qds);
        parseIec104Cp56Time2a(&genericIOGroup->m_me_td_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ME_TE_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_te_1IOGroup->ioa);
        }
        parseIec104Sva(&genericIOGroup->m_me_te_1IOSubgroup->sva);
        parseIec104Qds(&genericIOGroup->m_me_te_1IOSubgroup->qds);
        parseIec104Cp56Time2a(&genericIOGroup->m_me_te_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_ME_TF_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_me_tf_1IOGroup->ioa);
        }
        parseIec104IeeeStd754(&genericIOGroup->m_me_tf_1IOSubgroup->ieeeStd754);
        parseIec104Qds(&genericIOGroup->m_me_tf_1IOSubgroup->qds);
        parseIec104Cp56Time2a(&genericIOGroup->m_me_tf_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_IT_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_it_tb_1IOGroup->ioa);
        }
        parseIec104Bcr(&genericIOGroup->m_it_tb_1IOSubgroup->bcr);
        parseIec104Cp56Time2a(&genericIOGroup->m_it_tb_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_EP_TD_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ep_td_1IOGroup->ioa);
        }
        parseIec104Sep(&genericIOGroup->m_ep_td_1IOSubgroup->sep);
        parseIec104Cp16Time2a(&genericIOGroup->m_ep_td_1IOSubgroup->elapsedTime);
        parseIec104Cp56Time2a(&genericIOGroup->m_ep_td_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_EP_TE_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ep_te_1IOGroup->ioa);
        }
        parseIec104Sep(&genericIOGroup->m_ep_te_1IOSubgroup->sep);
        parseIec104Qdp(&genericIOGroup->m_ep_te_1IOSubgroup->qdp);
        parseIec104Cp16Time2a(&genericIOGroup->m_ep_te_1IOSubgroup->relayDurationTime);
        parseIec104Cp56Time2a(&genericIOGroup->m_ep_te_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_EP_TF_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ep_tf_1IOGroup->ioa);
        }
        parseIec104Oci(&genericIOGroup->m_ep_tf_1IOSubgroup->oci);
        parseIec104Qdp(&genericIOGroup->m_ep_tf_1IOSubgroup->qdp);
        parseIec104Cp16Time2a(&genericIOGroup->m_ep_tf_1IOSubgroup->relayDurationTime);
        parseIec104Cp56Time2a(&genericIOGroup->m_ep_tf_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_SC_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_sc_na_1IOGroup->ioa);
        }
        parseIec104Sco(&genericIOGroup->c_sc_na_1IOSubgroup->sco);
        break;
    }

    case IEC104_ASDU_C_DC_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_dc_na_1IOGroup->ioa);
        }
        parseIec104Dco(&genericIOGroup->c_dc_na_1IOSubgroup->dco);
        break;
    }

    case IEC104_ASDU_C_RC_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_rc_na_1IOGroup->ioa);
        }
        parseIec104Rco(&genericIOGroup->c_rc_na_1IOSubgroup->rco);
        break;
    }

    case IEC104_ASDU_C_SE_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_se_na_1IOGroup->ioa);
        }
        parseIec104Nva(&genericIOGroup->c_se_na_1IOSubgroup->nva);
        parseIec104Qos(&genericIOGroup->c_se_na_1IOSubgroup->qos);
        break;
    }

    case IEC104_ASDU_C_SE_NB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_se_nb_1IOGroup->ioa);
        }
        parseIec104Sva(&genericIOGroup->c_se_nb_1IOSubgroup->sva);
        parseIec104Qos(&genericIOGroup->c_se_nb_1IOSubgroup->qos);
        break;
    }

    case IEC104_ASDU_C_SE_NC_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_se_nc_1IOGroup->ioa);
        }
        parseIec104IeeeStd754(&genericIOGroup->c_se_nc_1IOSubgroup->ieeeStd754);
        parseIec104Qos(&genericIOGroup->c_se_nc_1IOSubgroup->qos);
        break;
    }

    case IEC104_ASDU_C_BO_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_bo_na_1IOGroup->ioa);
        }
        parseIec104Bsi(&genericIOGroup->c_bo_na_1IOSubgroup->bsi);
        break;
    }

    case IEC104_ASDU_C_SC_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_sc_ta_1IOGroup->ioa);
        }
        parseIec104Sco(&genericIOGroup->c_sc_ta_1IOSubgroup->sco);
        parseIec104Cp56Time2a(&genericIOGroup->c_sc_ta_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_DC_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_dc_ta_1IOGroup->ioa);
        }
        parseIec104Dco(&genericIOGroup->c_dc_ta_1IOSubgroup->dco);
        parseIec104Cp56Time2a(&genericIOGroup->c_dc_ta_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_RC_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_rc_ta_1IOGroup->ioa);
        }
        parseIec104Rco(&genericIOGroup->c_rc_ta_1IOSubgroup->rco);
        parseIec104Cp56Time2a(&genericIOGroup->c_rc_ta_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_SE_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_se_ta_1IOGroup->ioa);
        }
        parseIec104Nva(&genericIOGroup->c_se_ta_1IOSubgroup->nva);
        parseIec104Qos(&genericIOGroup->c_se_ta_1IOSubgroup->qos);
        parseIec104Cp56Time2a(&genericIOGroup->c_se_ta_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_SE_TB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_se_tb_1IOGroup->ioa);
        }
        parseIec104Sva(&genericIOGroup->c_se_tb_1IOSubgroup->sva);
        parseIec104Qos(&genericIOGroup->c_se_tb_1IOSubgroup->qos);
        parseIec104Cp56Time2a(&genericIOGroup->c_se_tb_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_SE_TC_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_se_tc_1IOGroup->ioa);
        }
        parseIec104IeeeStd754(&genericIOGroup->c_se_tc_1IOSubgroup->ieeeStd754);
        parseIec104Qos(&genericIOGroup->c_se_tc_1IOSubgroup->qos);
        parseIec104Cp56Time2a(&genericIOGroup->c_se_tc_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_BO_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_bo_ta_1IOGroup->ioa);
        }
        parseIec104Bsi(&genericIOGroup->c_bo_ta_1IOSubgroup->bsi);
        parseIec104Cp56Time2a(&genericIOGroup->c_bo_ta_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_M_EI_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->m_ei_na_1IOGroup->ioa);
        }
        parseIec104Coi(&genericIOGroup->m_ei_na_1IOSubgroup->coi);
        break;
    }

    case IEC104_ASDU_C_IC_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_ic_na_1IOGroup->ioa);
        }
        parseIec104Qoi(&genericIOGroup->c_ic_na_1IOSubgroup->qoi);
        break;
    }

    case IEC104_ASDU_C_CI_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_ci_na_1IOGroup->ioa);
        }
        parseIec104Qcc(&genericIOGroup->c_ci_na_1IOSubgroup->qcc);
        break;
    }

    case IEC104_ASDU_C_RD_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_rd_na_1IOGroup->ioa);
        }
        // no subgroup for this type
        break;
    }

    case IEC104_ASDU_C_CS_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_cs_na_1IOGroup->ioa);
        }
        parseIec104Cp56Time2a(&genericIOGroup->c_cs_na_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_C_TS_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_ts_na_1IOGroup->ioa);
        }
        parseIec104Fbp(&genericIOGroup->c_ts_na_1IOSubgroup->fbp);
        break;
    }

    case IEC104_ASDU_C_RP_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_rp_na_1IOGroup->ioa);
        }
        parseIec104Qrp(&genericIOGroup->c_rp_na_1IOSubgroup->qrp);
        break;
    }

    case IEC104_ASDU_C_CD_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_cd_na_1IOGroup->ioa);
        }
        parseIec104Cp16Time2a(&genericIOGroup->c_cd_na_1IOSubgroup->msUpToSeconds);
        break;
    }

    case IEC104_ASDU_C_TS_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->c_ts_ta_1IOGroup->ioa);
        }
        parseIec104Tsc(&genericIOGroup->c_ts_ta_1IOSubgroup->tsc);
        parseIec104Cp56Time2a(&genericIOGroup->c_ts_ta_1IOSubgroup->sevenOctetBinaryTime);
        break;
    }

    case IEC104_ASDU_P_ME_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->p_me_na_1IOGroup->ioa);
        }
        parseIec104Nva(&genericIOGroup->p_me_na_1IOSubgroup->nva);
        parseIec104Qpm(&genericIOGroup->p_me_na_1IOSubgroup->qpm);
        break;
    }

    case IEC104_ASDU_P_ME_NB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->p_me_nb_1IOGroup->ioa);
        }
        parseIec104Sva(&genericIOGroup->p_me_nb_1IOSubgroup->sva);
        parseIec104Qpm(&genericIOGroup->p_me_nb_1IOSubgroup->qpm);
        break;
    }

    case IEC104_ASDU_P_ME_NC_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->p_me_nc_1IOGroup->ioa);
        }
        parseIec104IeeeStd754(&genericIOGroup->p_me_nc_1IOSubgroup->ieeeStd754);
        parseIec104Qpm(&genericIOGroup->p_me_nc_1IOSubgroup->qpm);
        break;
    }

    case IEC104_ASDU_P_AC_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->p_ac_na_1IOGroup->ioa);
        }
        parseIec104Qpa(&genericIOGroup->p_ac_na_1IOSubgroup->qpa);
        break;
    }

    case IEC104_ASDU_F_FR_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_fr_na_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_fr_na_1IOSubgroup->nameOfFile);
        parseIec104Lof(&genericIOGroup->f_fr_na_1IOSubgroup->lengthOfFile);
        parseIec104Frq(&genericIOGroup->f_fr_na_1IOSubgroup->frq);
        break;
    }

    case IEC104_ASDU_F_SR_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_sr_na_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_sr_na_1IOSubgroup->nameOfFile);
        parseIec104Nos(&genericIOGroup->f_sr_na_1IOSubgroup->nameOfSection);
        parseIec104Lof(&genericIOGroup->f_sr_na_1IOSubgroup->lengthOfFileOrSection);
        parseIec104Srq(&genericIOGroup->f_sr_na_1IOSubgroup->srq);
        break;
    }

    case IEC104_ASDU_F_SC_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_sc_na_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_sc_na_1IOSubgroup->nameOfFile);
        parseIec104Nos(&genericIOGroup->f_sc_na_1IOSubgroup->nameOfSection);
        parseIec104Scq(&genericIOGroup->f_sc_na_1IOSubgroup->scq);
        break;
    }

    case IEC104_ASDU_F_LS_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_ls_na_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_ls_na_1IOSubgroup->nameOfFile);
        parseIec104Nos(&genericIOGroup->f_ls_na_1IOSubgroup->nameOfSection);
        parseIec104Lsq(&genericIOGroup->f_ls_na_1IOSubgroup->lsq);
        parseIec104Chs(&genericIOGroup->f_ls_na_1IOSubgroup->chs);
        break;
    }

    case IEC104_ASDU_F_AF_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_af_na_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_af_na_1IOSubgroup->nameOfFile);
        parseIec104Nos(&genericIOGroup->f_af_na_1IOSubgroup->nameOfSection);
        parseIec104Afq(&genericIOGroup->f_af_na_1IOSubgroup->afq);
        break;
    }

    case IEC104_ASDU_F_SG_NA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_sg_na_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_sg_na_1IOSubgroup->nameOfFile);
        parseIec104Nos(&genericIOGroup->f_sg_na_1IOSubgroup->nameOfSection);
        bool losValid = parseIec104Los(&genericIOGroup->f_sg_na_1IOSubgroup->lengthOfSegment,
            genericIOGroup->apduSize);
        // parse the segment when the LOS is deemed acceptable
        if (losValid)
        {
            for (uint8_t i = 0; i < genericIOGroup->f_sg_na_1IOSubgroup->lengthOfSegment.lengthOfSegment; i++)
            {
                parseIec104Segment(&genericIOGroup->f_sg_na_1IOSubgroup->segment);
            }
        }
        break;
    }

    case IEC104_ASDU_F_DR_TA_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_dr_ta_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_dr_ta_1IOSubgroup->nameOfFileOrSubdirectory);
        parseIec104Lof(&genericIOGroup->f_dr_ta_1IOSubgroup->lengthOfFile);
        parseIec104Sof(&genericIOGroup->f_dr_ta_1IOSubgroup->sof);
        parseIec104Cp56Time2a(&genericIOGroup->f_dr_ta_1IOSubgroup->creationTimeOfFile);
        break;
    }

    case IEC104_ASDU_F_SC_NB_1:
    {
        if (genericIOGroup->includeIOA)
        {
            parseIec104InformationObjectAddressWithThreeOctets(
                &genericIOGroup->f_sc_nb_1IOGroup->ioa);
        }
        parseIec104Nof(&genericIOGroup->f_sc_nb_1IOSubgroup->nameOfFile);
        parseIec104Cp56Time2a(&genericIOGroup->f_sc_nb_1IOSubgroup->startTime);
        parseIec104Cp56Time2a(&genericIOGroup->f_sc_nb_1IOSubgroup->stopTime);
        break;
    }

    default:
    {
        // passed ASDU type was not recognized
    }
    }
}

static void parseIec104GenericAsdu(uint32_t asduType, const Iec104ApciI* apci)
{
    uint32_t verifiedNumberOfElements = parseIec104Vsq(apci);
    parseIec104CauseOfTx(apci);
    parseIec104TwoOctetCommonAddress(apci);

    // Set up the generic group structure
    GenericIec104AsduIOGroup genericIOGroup;
    genericIOGroup.asduType = asduType;
    genericIOGroup.apduSize = apci->header.length;

    // make sure the number of elements value is acceptable
    if (verifiedNumberOfElements > 0 && verifiedNumberOfElements <= 255) {
        // iterate over the reported number of elements overlaying the structures
        for (uint32_t i = 0; i < verifiedNumberOfElements; i++)
        {

            //
            // Handle Structure Qualifier == 1
            //
            if (apci->asdu.variableStructureQualifier.sq)
            {
                // IOA should only be printed on the first iteration in SQ1
                if (i == 0)
                {
                    genericIOGroup.includeIOA = true;
                }
                else
                {
                    genericIOGroup.includeIOA = false;
                }

                // fill genericIOGroup with the appropriate asdu depending on the type
                switch (asduType)
                {
                case IEC104_ASDU_M_SP_NA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_sp_na_1IOGroup = &apci->asdu.m_sp_na_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_SP_NA_1_IO_Subgroup* curIo = &apci->asdu.m_sp_na_1.subgroup + i;
                    genericIOGroup.m_sp_na_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_SP_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_DP_NA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_dp_na_1IOGroup = &apci->asdu.m_dp_na_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_DP_NA_1_IO_Subgroup* curIo = &apci->asdu.m_dp_na_1.subgroup + i;
                    genericIOGroup.m_dp_na_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_DP_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_ST_NA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_st_na_1IOGroup = &apci->asdu.m_st_na_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_ST_NA_1_IO_Subgroup* curIo = &apci->asdu.m_st_na_1.subgroup + i;
                    genericIOGroup.m_st_na_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_ST_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_BO_NA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_bo_na_1IOGroup = &apci->asdu.m_bo_na_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_BO_NA_1_IO_Subgroup* curIo = &apci->asdu.m_bo_na_1.subgroup + i;
                    genericIOGroup.m_bo_na_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_BO_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_ME_NA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_me_na_1IOGroup = &apci->asdu.m_me_na_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_ME_NA_1_IO_Subgroup* curIo = &apci->asdu.m_me_na_1.subgroup + i;
                    genericIOGroup.m_me_na_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_ME_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_ME_NB_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_me_nb_1IOGroup = &apci->asdu.m_me_nb_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_ME_NB_1_IO_Subgroup* curIo = &apci->asdu.m_me_nb_1.subgroup + i;
                    genericIOGroup.m_me_nb_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_ME_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_ME_NC_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_me_nc_1IOGroup = &apci->asdu.m_me_nc_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_ME_NC_1_IO_Subgroup* curIo = &apci->asdu.m_me_nc_1.subgroup + i;
                    genericIOGroup.m_me_nc_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_ME_TC_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_IT_NA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_it_na_1IOGroup = &apci->asdu.m_it_na_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_IT_NA_1_IO_Subgroup* curIo = &apci->asdu.m_it_na_1.subgroup + i;
                    genericIOGroup.m_it_na_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_IT_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_EP_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_EP_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_EP_TC_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_M_PS_NA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_ps_na_1IOGroup = &apci->asdu.m_ps_na_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_PS_NA_1_IO_Subgroup* curIo = &apci->asdu.m_ps_na_1.subgroup + i;
                    genericIOGroup.m_ps_na_1IOSubgroup = curIo;

                    break;
                }

                case IEC104_ASDU_M_ME_ND_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.m_me_nd_1IOGroup = &apci->asdu.m_me_nd_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104M_ME_ND_1_IO_Subgroup* curIo = &apci->asdu.m_me_nd_1.subgroup + i;
                    genericIOGroup.m_me_nd_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_M_SP_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_DP_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_ST_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_BO_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_ME_TD_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_ME_TE_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_ME_TF_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_IT_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_EP_TD_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_EP_TE_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_EP_TF_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SC_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_DC_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_RC_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SE_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SE_NB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SE_NC_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_BO_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SC_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_DC_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_RC_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SE_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SE_TB_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_SE_TC_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_BO_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_M_EI_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_IC_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_CI_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_RD_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_CS_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_TS_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_RP_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_CD_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_C_TS_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                //case IEC104_ASDU_P_ME_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                //case IEC104_ASDU_P_ME_NB_1
                // path doesn't happen as it gets caught during the ASDU check

                //case IEC104_ASDU_P_ME_NC_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_P_AC_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_F_FR_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_F_SR_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_F_SC_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_F_LS_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_F_AF_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                // case IEC104_ASDU_F_SG_NA_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_F_DR_TA_1:
                {
                    // Since there is only one full IOGroup structure in SQ1 this can stay for all cases
                    genericIOGroup.f_dr_ta_1IOGroup = &apci->asdu.f_dr_ta_1;

                    // the subgroup pointer can be calculated by incrementing the first subgroup pointer by the iteration times the size of the subgroup pointer
                    // since `i` will be 0 on the first go round this works for all iterations
                    // since C adds based on the pointer type we only need to cast and increment
                    const Iec104F_DR_TA_1_IO_Subgroup* curIo = &apci->asdu.f_dr_ta_1.subgroup + i;
                    genericIOGroup.f_dr_ta_1IOSubgroup = curIo;

                    break;
                }

                // case IEC104_ASDU_F_SC_NB_1
                // path doesn't happen as it gets caught during the ASDU check

                default:
                {
                    // SQ1 ASDU parsing not implemented for this type
                }
                }

                // parse the new subgroup
                parseIec104GenericIOGroup(&genericIOGroup);

            }
            //
            // Handle Structure Qualifier == 0
            //
            else
            {
                // the IOA should always be included for SQ0
                genericIOGroup.includeIOA = true;

                // fill genericIOGroup with the appropriate asdu depending on the type
                switch (asduType)
                {
                case IEC104_ASDU_M_SP_NA_1:
                {
                    // increment the information object block pointer by the size of the M_SP_NA_1_IO_Group struct
                    const Iec104M_SP_NA_1_IO_Group* curIo =
                        (const Iec104M_SP_NA_1_IO_Group*) &apci->asdu.m_sp_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_sp_na_1IOGroup = curIo;
                    genericIOGroup.m_sp_na_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_SP_TA_1:
                {
                    // increment the information object block pointer by the size of the M_SP_TA_1_IO_Group struct
                    const Iec104M_SP_TA_1_IO_Group* curIo =
                        (const Iec104M_SP_TA_1_IO_Group*) &apci->asdu.m_sp_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_sp_ta_1IOGroup = curIo;
                    genericIOGroup.m_sp_ta_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_DP_NA_1:
                {
                    // increment the information object block pointer by the size of the M_DP_NA_1_IO_Group struct
                    const Iec104M_DP_NA_1_IO_Group* curIo =
                        (const Iec104M_DP_NA_1_IO_Group*) &apci->asdu.m_dp_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_dp_na_1IOGroup = curIo;
                    genericIOGroup.m_dp_na_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_DP_TA_1:
                {
                    // increment the information object block pointer by the size of the M_DP_TA_1_IO_Group struct
                    const Iec104M_DP_TA_1_IO_Group* curIo =
                        (const Iec104M_DP_TA_1_IO_Group*) &apci->asdu.m_dp_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_dp_ta_1IOGroup = curIo;
                    genericIOGroup.m_dp_ta_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ST_NA_1:
                {
                    // increment the information object block pointer by the size of the M_ST_NA_1_IO_Group struct
                    const Iec104M_ST_NA_1_IO_Group* curIo =
                        (const Iec104M_ST_NA_1_IO_Group*) &apci->asdu.m_st_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_st_na_1IOGroup = curIo;
                    genericIOGroup.m_st_na_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ST_TA_1:
                {
                    // increment the information object block pointer by the size of the M_ST_TA_1_IO_Group struct
                    const Iec104M_ST_TA_1_IO_Group* curIo =
                        (const Iec104M_ST_TA_1_IO_Group*) &apci->asdu.m_st_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_st_ta_1IOGroup = curIo;
                    genericIOGroup.m_st_ta_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_BO_NA_1:
                {
                    // increment the information object block pointer by the size of the M_BO_NA_1_IO_Group struct
                    const Iec104M_BO_NA_1_IO_Group* curIo =
                        (const Iec104M_BO_NA_1_IO_Group*) &apci->asdu.m_bo_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_bo_na_1IOGroup = curIo;
                    genericIOGroup.m_bo_na_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_BO_TA_1:
                {
                    // increment the information object block pointer by the size of the M_BO_TA_1_IO_Group struct
                    const Iec104M_BO_TA_1_IO_Group* curIo =
                        (const Iec104M_BO_TA_1_IO_Group*) &apci->asdu.m_bo_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_bo_ta_1IOGroup = curIo;
                    genericIOGroup.m_bo_ta_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ME_NA_1:
                {
                    // increment the information object block pointer by the size of the M_ME_NA_1_IO_Group struct
                    const Iec104M_ME_NA_1_IO_Group* curIo =
                        (const Iec104M_ME_NA_1_IO_Group*) &apci->asdu.m_me_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_na_1IOGroup = curIo;
                    genericIOGroup.m_me_na_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ME_TA_1:
                {
                    // increment the information object block pointer by the size of the M_ME_TA_1_IO_Group struct
                    const Iec104M_ME_TA_1_IO_Group* curIo =
                        (const Iec104M_ME_TA_1_IO_Group*) &apci->asdu.m_me_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_ta_1IOGroup = curIo;
                    genericIOGroup.m_me_ta_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ME_NB_1:
                {
                    // increment the information object block pointer by the size of the M_ME_NB_1_IO_Group struct
                    const Iec104M_ME_NB_1_IO_Group* curIo =
                        (const Iec104M_ME_NB_1_IO_Group*) &apci->asdu.m_me_nb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_nb_1IOGroup = curIo;
                    genericIOGroup.m_me_nb_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ME_TB_1:
                {
                    // increment the information object block pointer by the size of the M_ME_TB_1_IO_Group struct
                    const Iec104M_ME_TB_1_IO_Group* curIo =
                        (const Iec104M_ME_TB_1_IO_Group*) &apci->asdu.m_me_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_tb_1IOGroup = curIo;
                    genericIOGroup.m_me_tb_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ME_NC_1:
                {
                    // increment the information object block pointer by the size of the M_ME_NC_1_IO_Group struct
                    const Iec104M_ME_NC_1_IO_Group* curIo =
                        (const Iec104M_ME_NC_1_IO_Group*) &apci->asdu.m_me_nc_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_nc_1IOGroup = curIo;
                    genericIOGroup.m_me_nc_1IOSubgroup = &curIo->subgroup;

                    break;
                }

                case IEC104_ASDU_M_ME_TC_1:
                {
                    // increment the information object block pointer by the size of the M_ME_TC_1_IO_Group struct
                    const Iec104M_ME_TC_1_IO_Group* curIo =
                        (const Iec104M_ME_TC_1_IO_Group*) &apci->asdu.m_me_tc_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_tc_1IOGroup = curIo;
                    genericIOGroup.m_me_tc_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_IT_NA_1:
                {
                    // increment the information object block pointer by the size of the M_IT_NA_1_IO_Group struct
                    const Iec104M_IT_NA_1_IO_Group* curIo =
                        (const Iec104M_IT_NA_1_IO_Group*) &apci->asdu.m_it_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_it_na_1IOGroup = curIo;
                    genericIOGroup.m_it_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_IT_TA_1:
                {
                    // increment the information object block pointer by the size of the M_IT_TA_1_IO_Group struct
                    const Iec104M_IT_TA_1_IO_Group* curIo =
                        (const Iec104M_IT_TA_1_IO_Group*) &apci->asdu.m_it_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_it_ta_1IOGroup = curIo;
                    genericIOGroup.m_it_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_EP_TA_1:
                {
                    // increment the information object block pointer by the size of the M_EP_TA_1_IO_Group struct
                    const Iec104M_EP_TA_1_IO_Group* curIo =
                        (const Iec104M_EP_TA_1_IO_Group*) &apci->asdu.m_ep_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ep_ta_1IOGroup = curIo;
                    genericIOGroup.m_ep_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_EP_TB_1:
                {
                    // increment the information object block pointer by the size of the M_EP_TB_1_IO_Group struct
                    const Iec104M_EP_TB_1_IO_Group* curIo =
                        (const Iec104M_EP_TB_1_IO_Group*) &apci->asdu.m_ep_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ep_tb_1IOGroup = curIo;
                    genericIOGroup.m_ep_tb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_EP_TC_1:
                {
                    // increment the information object block pointer by the size of the M_EP_TC_1_IO_Group struct
                    const Iec104M_EP_TC_1_IO_Group* curIo =
                        (const Iec104M_EP_TC_1_IO_Group*) &apci->asdu.m_ep_tc_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ep_tc_1IOGroup = curIo;
                    genericIOGroup.m_ep_tc_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_PS_NA_1:
                {
                    // increment the information object block pointer by the size of the M_PS_NA_1_IO_Group struct
                    const Iec104M_PS_NA_1_IO_Group* curIo =
                        (const Iec104M_PS_NA_1_IO_Group*) &apci->asdu.m_ps_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ps_na_1IOGroup = curIo;
                    genericIOGroup.m_ps_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_ME_ND_1:
                {
                    // increment the information object block pointer by the size of the M_ME_ND_1_IO_Group struct
                    const Iec104M_ME_ND_1_IO_Group* curIo =
                        (const Iec104M_ME_ND_1_IO_Group*) &apci->asdu.m_me_nd_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_nd_1IOGroup = curIo;
                    genericIOGroup.m_me_nd_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_SP_TB_1:
                {
                    // increment the information object block pointer by the size of the M_SP_TB_1_IO_Group struct
                    const Iec104M_SP_TB_1_IO_Group* curIo =
                        (const Iec104M_SP_TB_1_IO_Group*) &apci->asdu.m_sp_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_sp_tb_1IOGroup = curIo;
                    genericIOGroup.m_sp_tb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_DP_TB_1:
                {
                    // increment the information object block pointer by the size of the M_DP_TB_1_IO_Group struct
                    const Iec104M_DP_TB_1_IO_Group* curIo =
                        (const Iec104M_DP_TB_1_IO_Group*) &apci->asdu.m_dp_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_dp_tb_1IOGroup = curIo;
                    genericIOGroup.m_dp_tb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_ST_TB_1:
                {
                    // increment the information object block pointer by the size of the M_ST_TB_1_IO_Group struct
                    const Iec104M_ST_TB_1_IO_Group* curIo =
                        (const Iec104M_ST_TB_1_IO_Group*) &apci->asdu.m_st_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_st_tb_1IOGroup = curIo;
                    genericIOGroup.m_st_tb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_BO_TB_1:
                {
                    // increment the information object block pointer by the size of the M_BO_TB_1_IO_Group struct
                    const Iec104M_BO_TB_1_IO_Group* curIo =
                        (const Iec104M_BO_TB_1_IO_Group*) &apci->asdu.m_bo_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_bo_tb_1IOGroup = curIo;
                    genericIOGroup.m_bo_tb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_ME_TD_1:
                {
                    // increment the information object block pointer by the size of the M_ME_TD_1_IO_Group struct
                    const Iec104M_ME_TD_1_IO_Group* curIo =
                        (const Iec104M_ME_TD_1_IO_Group*) &apci->asdu.m_me_td_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_td_1IOGroup = curIo;
                    genericIOGroup.m_me_td_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_ME_TE_1:
                {
                    // increment the information object block pointer by the size of the M_ME_TE_1_IO_Group struct
                    const Iec104M_ME_TE_1_IO_Group* curIo =
                        (const Iec104M_ME_TE_1_IO_Group*) &apci->asdu.m_me_te_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_te_1IOGroup = curIo;
                    genericIOGroup.m_me_te_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_ME_TF_1:
                {
                    // increment the information object block pointer by the size of the M_ME_TF_1_IO_Group struct
                    const Iec104M_ME_TF_1_IO_Group* curIo =
                        (const Iec104M_ME_TF_1_IO_Group*) &apci->asdu.m_me_tf_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_me_tf_1IOGroup = curIo;
                    genericIOGroup.m_me_tf_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_IT_TB_1:
                {
                    // increment the information object block pointer by the size of the M_IT_TB_1_IO_Group struct
                    const Iec104M_IT_TB_1_IO_Group* curIo =
                        (const Iec104M_IT_TB_1_IO_Group*) &apci->asdu.m_it_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_it_tb_1IOGroup = curIo;
                    genericIOGroup.m_it_tb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_EP_TD_1:
                {
                    // increment the information object block pointer by the size of the M_EP_TD_1_IO_Group struct
                    const Iec104M_EP_TD_1_IO_Group* curIo =
                        (const Iec104M_EP_TD_1_IO_Group*) &apci->asdu.m_ep_td_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ep_td_1IOGroup = curIo;
                    genericIOGroup.m_ep_td_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_EP_TE_1:
                {
                    // increment the information object block pointer by the size of the M_EP_TE_1_IO_Group struct
                    const Iec104M_EP_TE_1_IO_Group* curIo =
                        (const Iec104M_EP_TE_1_IO_Group*) &apci->asdu.m_ep_te_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ep_te_1IOGroup = curIo;
                    genericIOGroup.m_ep_te_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_EP_TF_1:
                {
                    // increment the information object block pointer by the size of the M_EP_TF_1_IO_Group struct
                    const Iec104M_EP_TF_1_IO_Group* curIo =
                        (const Iec104M_EP_TF_1_IO_Group*) &apci->asdu.m_ep_tf_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ep_tf_1IOGroup = curIo;
                    genericIOGroup.m_ep_tf_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SC_NA_1:
                {
                    // increment the information object block pointer by the size of the C_SC_NA_1_IO_Group struct
                    const Iec104C_SC_NA_1_IO_Group* curIo =
                        (const Iec104C_SC_NA_1_IO_Group*) &apci->asdu.c_sc_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_sc_na_1IOGroup = curIo;
                    genericIOGroup.c_sc_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_DC_NA_1:
                {
                    // increment the information object block pointer by the size of the C_DC_NA_1_IO_Group struct
                    const Iec104C_DC_NA_1_IO_Group* curIo =
                        (const Iec104C_DC_NA_1_IO_Group*) &apci->asdu.c_dc_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_dc_na_1IOGroup = curIo;
                    genericIOGroup.c_dc_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_RC_NA_1:
                {
                    // increment the information object block pointer by the size of the C_RC_NA_1_IO_Group struct
                    const Iec104C_RC_NA_1_IO_Group* curIo =
                        (const Iec104C_RC_NA_1_IO_Group*) &apci->asdu.c_rc_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_rc_na_1IOGroup = curIo;
                    genericIOGroup.c_rc_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SE_NA_1:
                {
                    // increment the information object block pointer by the size of the C_SE_NA_1_IO_Group struct
                    const Iec104C_SE_NA_1_IO_Group* curIo =
                        (const Iec104C_SE_NA_1_IO_Group*) &apci->asdu.c_se_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_se_na_1IOGroup = curIo;
                    genericIOGroup.c_se_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SE_NB_1:
                {
                    // increment the information object block pointer by the size of the C_SE_NB_1_IO_Group struct
                    const Iec104C_SE_NB_1_IO_Group* curIo =
                        (const Iec104C_SE_NB_1_IO_Group*) &apci->asdu.c_se_nb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_se_nb_1IOGroup = curIo;
                    genericIOGroup.c_se_nb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SE_NC_1:
                {
                    // increment the information object block pointer by the size of the C_SE_NC_1_IO_Group struct
                    const Iec104C_SE_NC_1_IO_Group* curIo =
                        (const Iec104C_SE_NC_1_IO_Group*) &apci->asdu.c_se_nc_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_se_nc_1IOGroup = curIo;
                    genericIOGroup.c_se_nc_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_BO_NA_1:
                {
                    // increment the information object block pointer by the size of the C_BO_NA_1_IO_Group struct
                    const Iec104C_BO_NA_1_IO_Group* curIo =
                        (const Iec104C_BO_NA_1_IO_Group*) &apci->asdu.c_bo_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_bo_na_1IOGroup = curIo;
                    genericIOGroup.c_bo_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SC_TA_1:
                {
                    // increment the information object block pointer by the size of the C_SC_TA_1_IO_Group struct
                    const Iec104C_SC_TA_1_IO_Group* curIo =
                        (const Iec104C_SC_TA_1_IO_Group*) &apci->asdu.c_sc_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_sc_ta_1IOGroup = curIo;
                    genericIOGroup.c_sc_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_DC_TA_1:
                {
                    // increment the information object block pointer by the size of the C_DC_TA_1_IO_Group struct
                    const Iec104C_DC_TA_1_IO_Group* curIo =
                        (const Iec104C_DC_TA_1_IO_Group*) &apci->asdu.c_dc_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_dc_ta_1IOGroup = curIo;
                    genericIOGroup.c_dc_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_RC_TA_1:
                {
                    // increment the information object block pointer by the size of the C_RC_TA_1_IO_Group struct
                    const Iec104C_RC_TA_1_IO_Group* curIo =
                        (const Iec104C_RC_TA_1_IO_Group*) &apci->asdu.c_rc_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_rc_ta_1IOGroup = curIo;
                    genericIOGroup.c_rc_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SE_TA_1:
                {
                    // increment the information object block pointer by the size of the C_SE_TA_1_IO_Group struct
                    const Iec104C_SE_TA_1_IO_Group* curIo =
                        (const Iec104C_SE_TA_1_IO_Group*) &apci->asdu.c_se_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_se_ta_1IOGroup = curIo;
                    genericIOGroup.c_se_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SE_TB_1:
                {
                    // increment the information object block pointer by the size of the C_SE_TB_1_IO_Group struct
                    const Iec104C_SE_TB_1_IO_Group* curIo =
                        (const Iec104C_SE_TB_1_IO_Group*) &apci->asdu.c_se_tb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_se_tb_1IOGroup = curIo;
                    genericIOGroup.c_se_tb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_SE_TC_1:
                {
                    // increment the information object block pointer by the size of the C_SE_TC_1_IO_Group struct
                    const Iec104C_SE_TC_1_IO_Group* curIo =
                        (const Iec104C_SE_TC_1_IO_Group*) &apci->asdu.c_se_tc_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_se_tc_1IOGroup = curIo;
                    genericIOGroup.c_se_tc_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_BO_TA_1:
                {
                    // increment the information object block pointer by the size of the C_BO_TA_1_IO_Group struct
                    const Iec104C_BO_TA_1_IO_Group* curIo =
                        (const Iec104C_BO_TA_1_IO_Group*) &apci->asdu.c_bo_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_bo_ta_1IOGroup = curIo;
                    genericIOGroup.c_bo_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_M_EI_NA_1:
                {
                    // increment the information object block pointer by the size of the M_EI_NA_1_IO_Group struct
                    const Iec104M_EI_NA_1_IO_Group* curIo =
                        (const Iec104M_EI_NA_1_IO_Group*) &apci->asdu.m_ei_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.m_ei_na_1IOGroup = curIo;
                    genericIOGroup.m_ei_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_IC_NA_1:
                {
                    // increment the information object block pointer by the size of the C_IC_NA_1_IO_Group struct
                    const Iec104C_IC_NA_1_IO_Group* curIo =
                        (const Iec104C_IC_NA_1_IO_Group*) &apci->asdu.c_ic_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_ic_na_1IOGroup = curIo;
                    genericIOGroup.c_ic_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_CI_NA_1:
                {
                    // increment the information object block pointer by the size of the C_CI_NA_1_IO_Group struct
                    const Iec104C_CI_NA_1_IO_Group* curIo =
                        (const Iec104C_CI_NA_1_IO_Group*) &apci->asdu.c_ci_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_ci_na_1IOGroup = curIo;
                    genericIOGroup.c_ci_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_RD_NA_1:
                {
                    // increment the information object block pointer by the size of the C_RD_NA_1_IO_Group struct
                    const Iec104C_RD_NA_1_IO_Group* curIo =
                        (const Iec104C_RD_NA_1_IO_Group*) &apci->asdu.c_rd_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_rd_na_1IOGroup = curIo;
                    genericIOGroup.c_rd_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_CS_NA_1:
                {
                    // increment the information object block pointer by the size of the C_CS_NA_1_IO_Group struct
                    const Iec104C_CS_NA_1_IO_Group* curIo =
                        (const Iec104C_CS_NA_1_IO_Group*) &apci->asdu.c_cs_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_cs_na_1IOGroup = curIo;
                    genericIOGroup.c_cs_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_TS_NA_1:
                {
                    // increment the information object block pointer by the size of the C_TS_NA_1_IO_Group struct
                    const Iec104C_TS_NA_1_IO_Group* curIo =
                        (const Iec104C_TS_NA_1_IO_Group*) &apci->asdu.c_ts_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_ts_na_1IOGroup = curIo;
                    genericIOGroup.c_ts_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_RP_NA_1:
                {
                    // increment the information object block pointer by the size of the C_RP_NA_1_IO_Group struct
                    const Iec104C_RP_NA_1_IO_Group* curIo =
                        (const Iec104C_RP_NA_1_IO_Group*) &apci->asdu.c_rp_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_rp_na_1IOGroup = curIo;
                    genericIOGroup.c_rp_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_CD_NA_1:
                {
                    // increment the information object block pointer by the size of the C_CD_NA_1_IO_Group struct
                    const Iec104C_CD_NA_1_IO_Group* curIo =
                        (const Iec104C_CD_NA_1_IO_Group*) &apci->asdu.c_cd_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_cd_na_1IOGroup = curIo;
                    genericIOGroup.c_cd_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_C_TS_TA_1:
                {
                    // increment the information object block pointer by the size of the C_TS_TA_1_IO_Group struct
                    const Iec104C_TS_TA_1_IO_Group* curIo =
                        (const Iec104C_TS_TA_1_IO_Group*) &apci->asdu.c_ts_ta_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.c_ts_ta_1IOGroup = curIo;
                    genericIOGroup.c_ts_ta_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_P_ME_NA_1:
                {
                    // increment the information object block pointer by the size of the P_ME_NA_1_IO_Group struct
                    const Iec104P_ME_NA_1_IO_Group* curIo =
                        (const Iec104P_ME_NA_1_IO_Group*) &apci->asdu.p_me_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.p_me_na_1IOGroup = curIo;
                    genericIOGroup.p_me_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_P_ME_NB_1:
                {
                    // increment the information object block pointer by the size of the P_ME_NB_1_IO_Group struct
                    const Iec104P_ME_NB_1_IO_Group* curIo =
                        (const Iec104P_ME_NB_1_IO_Group*) &apci->asdu.p_me_nb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.p_me_nb_1IOGroup = curIo;
                    genericIOGroup.p_me_nb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_P_ME_NC_1:
                {
                    // increment the information object block pointer by the size of the P_ME_NC_1_IO_Group struct
                    const Iec104P_ME_NC_1_IO_Group* curIo =
                        (const Iec104P_ME_NC_1_IO_Group*) &apci->asdu.p_me_nc_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.p_me_nc_1IOGroup = curIo;
                    genericIOGroup.p_me_nc_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_P_AC_NA_1:
                {
                    // increment the information object block pointer by the size of the P_AC_NA_1_IO_Group struct
                    const Iec104P_AC_NA_1_IO_Group* curIo =
                        (const Iec104P_AC_NA_1_IO_Group*) &apci->asdu.p_ac_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.p_ac_na_1IOGroup = curIo;
                    genericIOGroup.p_ac_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_F_FR_NA_1:
                {
                    // increment the information object block pointer by the size of the F_FR_NA_1_IO_Group struct
                    const Iec104F_FR_NA_1_IO_Group* curIo =
                        (const Iec104F_FR_NA_1_IO_Group*) &apci->asdu.f_fr_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.f_fr_na_1IOGroup = curIo;
                    genericIOGroup.f_fr_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_F_SR_NA_1:
                {
                    // increment the information object block pointer by the size of the F_SR_NA_1_IO_Group struct
                    const Iec104F_SR_NA_1_IO_Group* curIo =
                        (const Iec104F_SR_NA_1_IO_Group*) &apci->asdu.f_sr_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.f_sr_na_1IOGroup = curIo;
                    genericIOGroup.f_sr_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_F_SC_NA_1:
                {
                    // increment the information object block pointer by the size of the F_SC_NA_1_IO_Group struct
                    const Iec104F_SC_NA_1_IO_Group* curIo =
                        (const Iec104F_SC_NA_1_IO_Group*) &apci->asdu.f_sc_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.f_sc_na_1IOGroup = curIo;
                    genericIOGroup.f_sc_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_F_LS_NA_1:
                {
                    // increment the information object block pointer by the size of the F_LS_NA_1_IO_Group struct
                    const Iec104F_LS_NA_1_IO_Group* curIo =
                        (const Iec104F_LS_NA_1_IO_Group*) &apci->asdu.f_ls_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.f_ls_na_1IOGroup = curIo;
                    genericIOGroup.f_ls_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_F_AF_NA_1:
                {
                    // increment the information object block pointer by the size of the F_AF_NA_1_IO_Group struct
                    const Iec104F_AF_NA_1_IO_Group* curIo =
                        (const Iec104F_AF_NA_1_IO_Group*) &apci->asdu.f_af_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.f_af_na_1IOGroup = curIo;
                    genericIOGroup.f_af_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                case IEC104_ASDU_F_SG_NA_1:
                {
                    // increment the information object block pointer by the size of the F_SG_NA_1_IO_Group struct
                    const Iec104F_SG_NA_1_IO_Group* curIo =
                        (const Iec104F_SG_NA_1_IO_Group*) &apci->asdu.f_sg_na_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.f_sg_na_1IOGroup = curIo;
                    genericIOGroup.f_sg_na_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                // case IEC104_ASDU_F_DR_TA_1
                // path doesn't happen as it gets caught during the ASDU check

                case IEC104_ASDU_F_SC_NB_1:
                {
                    // increment the information object block pointer by the size of the F_SC_NB_1_IO_Group struct
                    const Iec104F_SC_NB_1_IO_Group* curIo =
                        (const Iec104F_SC_NB_1_IO_Group*) &apci->asdu.f_sc_nb_1 + i;

                    // print the SQ0 IO block
                    genericIOGroup.f_sc_nb_1IOGroup = curIo;
                    genericIOGroup.f_sc_nb_1IOSubgroup = &curIo->subgroup;
                    break;
                }

                default:
                {
                    // SQ0 ASDU parsing not implemented for this type
                }
                }

                // parse the group
                parseIec104GenericIOGroup(&genericIOGroup);
            }
        }
    }
}

void parseIec104ApciU(const Iec104ApciU* apci)
{
    // throw an alert if the start value is not 0x68
    if (apci->header.start != IEC104_START_BYTE)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_START);
    }
    // throw an alert if any length other than 0x04 is provided since this APCI can only have 4 bytes of data
    // a similar length check is performed in `iec104.c` when determining packet size. It is possible for that check to pass and this one alert
    else if (apci->header.length != IEC104_APCI_TYPE_U_LEN)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_LENGTH);
    }
    // initial APCI validation has passed
    else
    {
        // alert on use of reserved field
        if (apci->reserved1 || apci->reserved2 || apci->reserved3)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_APCIU_RESERVED_FIELD_IN_USE);
        }

        // make sure that only one of the fields is set
        uint32_t setCount = 0;
        setCount += apci->startdtAct;
        setCount += apci->startdtCon;
        setCount += apci->stopdtAct;
        setCount += apci->stopdtCon;
        setCount += apci->testfrAct;
        setCount += apci->testfrCon;
        if (setCount == 0 || setCount > 1)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_APCIU_INVALID_MESSAGE_TYPE);
        }
    }
}

void parseIec104ApciS(const Iec104ApciS* apci)
{
    // throw an alert if the start value is not 0x68
    if (apci->header.start != IEC104_START_BYTE)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_START);
    }
    // throw an alert if any length other than 0x04 is provided since this APCI can only have 4 bytes of data
    // a similar length check is performed in `iec104.c` when determining packet size. It is possible for that check to pass and this one alert
    else if (apci->header.length != IEC104_APCI_TYPE_S_LEN)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_LENGTH);
    }
    // initial APCI validation has passed
    else
    {
        // alert on use of reserved field
        if (apci->reserved1 || apci->reserved2)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_APCIS_RESERVED_FIELD_IN_USE);
        }
    }
}

void parseIec104ApciI(const Iec104ApciI* apci)
{
    // throw an alert if the start value is not 0x68
    if (apci->header.start != IEC104_START_BYTE)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_START);
    }
    // throw an alert if any length under 12 is detected as that is the smallest possible message according to the spec
    // a similar length check is performed in `iec104.c` when determining packet size. It is possible for that check to pass and this one alert
    else if (apci->header.length < IEC104_APCI_TYPE_I_MIN_LEN)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_LENGTH);
    }
    // initial APCI validation has passed
    else
    {
        // set up the ASDU check structure
        Iec104AsduCheck curAsduCheck;
        curAsduCheck.apci = apci;
        curAsduCheck.sq0Allowed = true;
        curAsduCheck.sq1Allowed = false;
        curAsduCheck.multipleIOAllowed = false;
        curAsduCheck.checkCauseOfTx = { };

        // select the appropriate asdu based on typeId value
        switch (apci->asdu.typeId)
        {

        case IEC104_ASDU_M_SP_NA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_SP_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_SP_TA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_SP_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_DP_NA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_DP_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_DP_TA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_DP_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ST_NA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ST_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ST_TA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ST_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_BO_NA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_BO_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_BO_TA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_BO_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_NA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.percyc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_TA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_NB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.percyc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_NB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_TB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_NC_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.percyc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_NC_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_TC_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_TC_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_IT_NA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqcogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco4 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_IT_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_IT_TA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqcogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco4 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_IT_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_EP_TA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_EP_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_EP_TB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_EP_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_EP_TC_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_EP_TC_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_PS_NA_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_PS_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_ND_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.percyc = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.back = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_ND_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_SP_TB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_SP_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_DP_TB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_DP_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ST_TB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retrem = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.retloc = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ST_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_BO_TB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_BO_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_TD_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_TD_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_TE_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_TE_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_ME_TF_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_ME_TF_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_IT_TB_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqcogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.reqco4 = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_IT_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_EP_TD_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_EP_TD_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_EP_TE_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_EP_TE_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_EP_TF_1:
        {
            // run checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_EP_TF_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SC_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SC_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_DC_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_DC_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_RC_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_RC_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SE_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SE_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SE_NB_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SE_NB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SE_NC_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SE_NC_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_BO_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_BO_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SC_TA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SC_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_DC_TA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_DC_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_RC_TA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_RC_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SE_TA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SE_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SE_TB_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SE_TB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_SE_TC_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_SE_TC_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_BO_TA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_BO_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_M_EI_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.init = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_M_EI_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_IC_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_IC_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_CI_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actterm = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_CI_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_RD_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_RD_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_CS_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_CS_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_TS_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_TS_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_RP_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_RP_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_CD_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_CD_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_C_TS_TA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_C_TS_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_P_ME_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_P_ME_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_P_ME_NB_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_P_ME_NB_1, apci);
            }
            break;
        }

        case IEC104_ASDU_P_ME_NC_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inrogen = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro1 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro2 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro3 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro4 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro5 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro6 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro7 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro8 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro9 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro10 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro11 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro12 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro13 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro14 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro15 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.inro16 = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_P_ME_NC_1, apci);
            }
            break;
        }

        case IEC104_ASDU_P_AC_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.act = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.actcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deact = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.deactcon = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_P_AC_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_FR_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.file = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_FR_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_SR_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.file = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_SR_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_SC_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.file = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_SC_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_LS_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.file = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_LS_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_AF_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.file = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_AF_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_SG_NA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.file = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_SG_NA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_DR_TA_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = false;
            curAsduCheck.sq1Allowed = true;
            curAsduCheck.multipleIOAllowed = true;
            curAsduCheck.checkCauseOfTx.spont = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.req = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_DR_TA_1, apci);
            }
            break;
        }

        case IEC104_ASDU_F_SC_NB_1:
        {
            // run generic checks against the asdu before continuing
            curAsduCheck.sq0Allowed = true;
            curAsduCheck.sq1Allowed = false;
            curAsduCheck.multipleIOAllowed = false;
            curAsduCheck.checkCauseOfTx.file = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_type_id = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_cause_tx = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_common_addr = IEC104_CTX_ALLOWED;
            curAsduCheck.checkCauseOfTx.unk_info_addr = IEC104_CTX_ALLOWED;

            if (checkIec104Asdu(curAsduCheck))
            {
                // parse the asdu if checks pass
                parseIec104GenericAsdu(IEC104_ASDU_F_SC_NB_1, apci);
            }
            break;
        }

        default:
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_ASDU_TYPE);
            break;
        }
        }
    }
}

