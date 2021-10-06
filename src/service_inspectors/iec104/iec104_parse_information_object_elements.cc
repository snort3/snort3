//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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

// iec104_parse_information_object_elements.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iec104_parse_information_object_elements.h"

#include <cmath>

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "protocols/packet.h"

#include "iec104.h"
#include "iec104_decode.h"
#include "iec104_module.h"

using namespace snort;

//
// Information Object Structures Parsing
//
//   This section contains functions to handle parsing and printing of the
//   various Information Object structures that make up the ASDU contents
//

// COI: Cause of Initialization Structure
void parseIec104Coi(const Iec104CoiType* coi)
{
    // throw an alert when the cause is in the reserved ranges (3-127)
    if (coi->ui >= IEC104_COI_UI_RES3)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_COI);
    }
}

// QOI: Qualifier of Interrogation Structure
void parseIec104Qoi(const Iec104QoiType* qoi)
{
    // throw an alert when the cause is in the reserved ranges
    if (qoi->qoi >= IEC104_QOI_RES1 and qoi->qoi <= IEC104_QOI_RES19)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QOI);
    }
    else if (qoi->qoi >= IEC104_QOI_RES37)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QOI);
    }
}

// QCC: Qualifier of Counter Interrogation Command Structure
void parseIec104Qcc(const Iec104QccType* qcc)
{
    // throw an alert when a reserved or invalid value is set
    if (qcc->rqt >= IEC104_QCC_RQT_RES32)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QCC);
    }
}

// QPM: Qualifier of Parameter of Measured Values Structure
void parseIec104Qpm(const Iec104QpmType* qpm)
{
    // throw an alert when a reserved or invalid value is set
    if (qpm->kpa >= IEC104_QPM_KPA_RES5)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QPM_KPA);
    }

    if (qpm->lpc)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_ABNORMAL_QPM_LPC);
    }

    if (qpm->pop)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_ABNORMAL_QPM_POP);
    }
}

// QPA: Qualifier of Parameter Activation Structure
void parseIec104Qpa(const Iec104QpaType* qpa)
{
    // throw an alert when a reserved or invalid value is set
    if (qpa->qpa >= IEC104_QPA_RES4)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QPA);
    }
}

// QOC: Qualifier of Command Structure
void parseIec104Qoc(uint8_t qu, uint8_t se)
{
    // throw an alert when a reserved or invalid value is set
    if (qu >= IEC104_QOC_QU_RES4 and qu <= IEC104_QOC_QU_RES31)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QOC);
    }

    if (se >= 2)
    {
        // error indicating that parsing couldn't finish
    }
}

// QRP: Qualifier of Reset Process Structure
void parseIec104Qrp(const Iec104QrpType* qrp)
{
    // throw an alert when a reserved or invalid value is set
    if (qrp->qrp >= IEC104_QRP_RES3)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QRP);
    }
}

// FRQ: File Ready Qualifier Structure
void parseIec104Frq(const Iec104FrqType* frq)
{
    // throw an alert when a reserved or invalid value is set
    if (frq->ui >= IEC104_FRQ_UI_RES1)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_FRQ);
    }
}

// SRQ: Section Ready Qualifier Structure
void parseIec104Srq(const Iec104SrqType* srq)
{
    // throw an alert when a reserved or invalid value is set
    if (srq->ui >= IEC104_SRQ_UI_RES1)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SRQ);
    }
}

// SCQ: Select and Call Qualifier Structure
void parseIec104Scq(const Iec104ScqType* scq)
{
    // throw an alert when a reserved or invalid value is set
    if (scq->ui1 >= IEC104_SCQ_UI1_RES8)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SCQ);
    }

    if (scq->ui2 >= IEC104_SCQ_UI2_RES6)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SCQ);
    }
}

// LSQ: Last Section or Segment Qualifier Structure
void parseIec104Lsq(const Iec104LsqType* lsq)
{
    // throw an alert when a reserved or invalid value is set
    if (lsq->lsq >= IEC104_LSQ_RES5)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_LSQ);
    }
}

// AFQ: Acknowledge File or Section Qualifier Structure
void parseIec104Afq(const Iec104AfqType* afq)
{
    // throw an alert when a reserved or invalid value is set
    if (afq->ui1 >= IEC104_AFQ_UI1_RES5)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_AFQ);
    }
    if (afq->ui2 >= IEC104_AFQ_UI2_RES6)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_AFQ);
    }
}

uint32_t parseIec104Vsq(const Iec104ApciI* apci)
{
    // number of elements == 0 is caught in check apdu

    uint32_t informationObjectSubgroupSize = 0;

    // determine the size of the current message type group
    switch(apci->asdu.typeId)
    {
        case IEC104_ASDU_M_SP_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_SP_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_SP_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_SP_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_DP_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_DP_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_DP_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_DP_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ST_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ST_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ST_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ST_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_BO_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_BO_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_BO_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_BO_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_NB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_NB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_NC_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_NC_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_TC_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_TC_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_IT_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_IT_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_IT_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_IT_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_EP_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_EP_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_EP_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_EP_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_EP_TC_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_EP_TC_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_PS_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_PS_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_ND_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_ND_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_SP_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_SP_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_DP_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_DP_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ST_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ST_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_BO_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_BO_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_TD_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_TD_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_TE_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_TE_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_ME_TF_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_ME_TF_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_IT_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_IT_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_EP_TD_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_EP_TD_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_EP_TE_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_EP_TE_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_EP_TF_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_EP_TF_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SC_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SC_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_DC_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_DC_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_RC_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_RC_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SE_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SE_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SE_NB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SE_NB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SE_NC_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SE_NC_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_BO_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_BO_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SC_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SC_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_DC_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_DC_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_RC_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_RC_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SE_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SE_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SE_TB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SE_TB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_SE_TC_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_SE_TC_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_BO_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_BO_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_M_EI_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104M_EI_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_IC_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_IC_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_CI_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_CI_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_RD_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_RD_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_CS_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_CS_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_TS_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_TS_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_RP_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_RP_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_CD_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_CD_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_C_TS_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104C_TS_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_P_ME_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104P_ME_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_P_ME_NB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104P_ME_NB_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_P_ME_NC_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104P_ME_NC_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_P_AC_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104P_AC_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_FR_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_FR_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_SR_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_SR_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_SC_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_SC_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_LS_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_LS_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_AF_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_AF_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_SG_NA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_SG_NA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_DR_TA_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_DR_TA_1_IO_Subgroup);
            break;
        }
        case IEC104_ASDU_F_SC_NB_1:
        {
            informationObjectSubgroupSize = sizeof(Iec104F_SC_NB_1_IO_Subgroup);
            break;
        }
    }

    // make sure the reported number of elements would not exceed the packet size
    // * take the apci->header.length value
    // * subtract off type id, vsq, cause of tx, and 2-byte common address sizes
    // * if the sq bit is set, subtract off the IOA
    // * use a switch statement with cases of each message type to get the size of one group
    // * divide the result of the earlier calculation by this group size to get the maximum allowable groups without overflowing
    uint8_t maxNumberOfElements = 0;

    if (informationObjectSubgroupSize)
    {
        uint32_t reported_msg_len = apci->header.length;
        if (reported_msg_len >= IEC104_APCI_TYPE_I_MIN_LEN) {
            if (apci->asdu.variableStructureQualifier.sq == 0)
            {
                uint32_t informationObjectGroupSize = informationObjectSubgroupSize + sizeof(const Iec104InformationObjectAddressThreeOctetType);
                maxNumberOfElements = (reported_msg_len
                                       - sizeof(uint8_t)  // type id
                                       - sizeof(const Iec104VariableStructureQualifierType)
                                       - sizeof(const Iec104CauseOfTransmissionType)
                                       - sizeof(const Iec104CommonAddressOfAsduType)
                                       ) / informationObjectGroupSize;
            }
            else
            {
                maxNumberOfElements = (reported_msg_len
                                       - sizeof(uint8_t)  // type id
                                       - sizeof(const Iec104VariableStructureQualifierType)
                                       - sizeof(const Iec104CauseOfTransmissionType)
                                       - sizeof(const Iec104CommonAddressOfAsduType)
                                       - sizeof(const Iec104InformationObjectAddressThreeOctetType)
                                       ) / informationObjectSubgroupSize;
            }
        }
    }

    uint32_t verifiedNumberOfElements = apci->asdu.variableStructureQualifier.numberOfElements;
    if (verifiedNumberOfElements > 0 and verifiedNumberOfElements <= maxNumberOfElements)
    {
        // do nothing
    }
    else
    {
        verifiedNumberOfElements = 0;
        DetectionEngine::queue_event(GID_IEC104, IEC104_APCII_INVALID_NUM_ELEMENTS_VALUE);
    }

    // if the SQ is set and the number of elements is only one something is off
    // this case does not apply in cases where the SQ bit being set is the only option
    // the only place this is known to exist is in F_DR_TA_1
    if (apci->asdu.variableStructureQualifier.sq > 0
        and apci->asdu.variableStructureQualifier.numberOfElements == 1
        and apci->asdu.typeId != IEC104_ASDU_F_DR_TA_1)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_VSQ_ABNORMAL_SQ);
    }


    return verifiedNumberOfElements;
}

void parseIec104CauseOfTx(const Iec104ApciI* apci)
{
    // no alerts are needed here as they are processed in checkIec104Asdu

    if (!apci)
    {
        // error indicating that parsing couldn't finish
    }
}

void parseIec104TwoOctetCommonAddress(const Iec104ApciI* apci)
{
    // provide an alert if a null common address is provided
    if (apci->asdu.commonAddressOfAsdu.commonAddress == 0)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_COMMON_ADDRESS);
    }
}

void parseIec104InformationObjectAddressWithThreeOctets(
    const Iec104InformationObjectAddressThreeOctetType* ioa)
{
    // Nothing worth alerting on here

    if (!ioa)
    {
        // error indicating that parsing couldn't finish
    }
}

// SIQ: Single Point Information with Quality Descriptor Structure
void parseIec104Siq(const Iec104SiqType* siq)
{
    // provide an alert if the reserved field is used
    if (siq->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SIQ);
    }
}

// DIQ: Double Point Information with Quality Descriptor Structure
void parseIec104Diq(const Iec104DiqType* diq)
{
    // provide an alert if the reserved field is used
    if (diq->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_DIQ);
    }
}

// QDS: Quality Descriptor Structure
void parseIec104Qds(const Iec104QdsType* qds)
{
    // provide an alert if the reserved field is used
    if (qds->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QDS);
    }
}

// QDP: Quality Descriptor for Events of Protection Equipment Structure
void parseIec104Qdp(const Iec104QdpType* qdp)
{
    // provide an alert if the reserved field is used
    if (qdp->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QDP);
    }
}

// VTI: Value with Transient State Indication Structure
void parseIec104Vti(const Iec104VtiType* vti)
{
    // Nothing worth alerting on here

    if (!vti)
    {
        // error indicating that parsing couldn't finish
    }
}

// NVA: Normalized Value Structure
void parseIec104Nva(const Iec104NvaType* nva)
{
    // Nothing worth alerting on here

    if (!nva)
    {
        // error indicating that parsing couldn't finish
    }
}

// SVA: Scaled Value Structure
void parseIec104Sva(const Iec104SvaType* sva)
{
    // Nothing worth alerting on here

    if (!sva)
    {
        // error indicating that parsing couldn't finish
    }
}

// IEEE_STD_754: Short Floating Point Number Structure
void parseIec104IeeeStd754(const Iec104IeeeStd754Type* ieeeStd754)
{
    //FIXIT-E: keep investigating possible alerts here

    // convert the passed IEEE Std 754 value to big endian
    uint32_t fixedIeeeStd754 = htonl(ieeeStd754->ieeeStd754);

    // break out individual fields for calculation
    // f == fraction, e == exponent, s == sign
    // +-----------------------------------------------------------------+
    // | 1                               0                               |
    // | f e d c b a 9 8 7 6 5 4 3 2 1 0 f e d c b a 9 8 7 6 5 4 3 2 1 0 |
    // +-----------------------------------------------------------------+
    // | s e e e e e e e e f f f f f f f f f f f f f f f f f f f f f f f |
    // +-----------------------------------------------------------------+
    uint32_t ieeeStd754RawFraction = fixedIeeeStd754 & 0x007FFFFF;
    uint8_t ieeeStd754RawExponent = (fixedIeeeStd754 >> 0x17) & 0xFF;

    // true exponent cannot be above 127 (raw 0xff)
    if (ieeeStd754RawExponent == 0xFF)
    {
        // alert on infinity if raw exponent == 0xff and fraction == 0x00
        if (ieeeStd754RawFraction == 0)
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_IEEE_STD_754_INFINITY);
        }
        // alert on NaN if raw exponent == 0xff and fraction > 0x00
        else
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_IEEE_STD_754_NAN);
        }
    }
}

// BCR: Binary Counter Reading Structure
void parseIec104Bcr(const Iec104BcrType* bcr)
{
    // Nothing worth alerting on here

    if (!bcr)
    {
        // error indicating that parsing couldn't finish
    }
}

// SEP: Single Event of Protection Equipment Structure
void parseIec104Sep(const Iec104SepType* sep)
{
    // provide an alert if the reserved field is used
    if (sep->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SEP);
    }
}

// SPE: Start Event of Protection Equipment Structure
void parseIec104Spe(const Iec104SpeType* spe)
{
    // provide an alert if the reserved field is used
    if (spe->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SPE);
    }
}

// OCI: Output Circuit Information Structure
void parseIec104Oci(const Iec104OciType* oci)
{
    // provide an alert if the reserved field is used
    if (oci->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_OCI);
    }
}

// BSI: Binary State Information Structure
void parseIec104Bsi(const Iec104BsiType* bsi)
{
    // Nothing worth alerting on here

    if (!bsi)
    {
        // error indicating that parsing couldn't finish
    }
}

// FBP: Fixed Test Bit Pattern Structure
void parseIec104Fbp(const Iec104FbpType* fbp)
{
    // provide an alert if the FBP is not \x55\xAA
    if (fbp->fixedTestBitPattern != 0x55AA)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_FBP);
    }
}

// SCO: Single Command Structure
void parseIec104Sco(const Iec104ScoType* sco)
{
    // provide an alert if the reserved field is used
    if (sco->reserved)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SCO);
    }

    // parse the Qualifier of Command structure
    parseIec104Qoc(sco->qu, sco->se);
}

// DCO: Double Command Structure
void parseIec104Dco(const Iec104DcoType* dco)
{
    // throw an alert when one of the defined invalid command states are detected
    if (dco->dcs == IEC104_DCO_DCS_NOTPERMITTED1 or dco->dcs == IEC104_DCO_DCS_NOTPERMITTED2)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_DCO);
    }

    // parse the Qualifier of Command structure
    parseIec104Qoc(dco->qu, dco->se);
}

// RCO: Regulating Step Command Structure
void parseIec104Rco(const Iec104RcoType* rco)
{
    // throw an alert when one of the defined invalid command states are detected
    if (rco->rcs == IEC104_RCO_RCS_NOTPERMITTED1 or rco->rcs == IEC104_RCO_RCS_NOTPERMITTED2)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_RCO);
    }

    // parse the Qualifier of Command structure
    parseIec104Qoc(rco->qu, rco->se);
}

// Time2a Milliseconds Structure
void parseIec104Time2aMilliseconds(const Iec104Time2aMillisecondsType* time2aMilliseconds)
{
    // ensure milliseconds aren't over the maximum allowed value
    if (time2aMilliseconds->milliseconds >= IEC104_MS_IN_MINUTE)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_MS_IN_MINUTE);
    }
}

// Time2a IVResMinute Structure
void parseIec104Time2aIvresminute(const Iec104Time2aIvresminuteType* time2aIvresminute)
{
    // ensure minutes arent over 59
    if (time2aIvresminute->minutes >= IEC104_MINS_IN_HOUR)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_MINS_IN_HOUR);
    }

    // provide an alert if the reserved field is used
    if (time2aIvresminute->res)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_MINS_IN_HOUR);
    }
}

// Time2a SURes2Hour Structure
void parseIec104Time2aSures2hour(const Iec104Time2aSures2hourType* time2aSures2hour)
{
    // ensure hours arent over 23
    if (time2aSures2hour->hours >= IEC104_HOURS_IN_DAY)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_HOURS_IN_DAY);
    }

    // provide an alert if the reserved field is used
    if (time2aSures2hour->res2)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_HOURS_IN_DAY);
    }
}

static bool isLeapYear(uint32_t yearOffset)
{
    // need to make sure we use the real year value and not just the offset
    uint32_t trueYear = IEC104_TIME2ARES4YEAR_BASE + yearOffset;

    // determine if the current year matches the following criteria:
    // (ref: https://docs.microsoft.com/en-us/office/troubleshoot/excel/determine-a-leap-year)
    //    1. If the year is evenly divisible by 4, go to step 2. Otherwise, go to step 5.
    //    2. If the year is evenly divisible by 100, go to step 3. Otherwise, go to step 4.
    //    3. If the year is evenly divisible by 400, go to step 4. Otherwise, go to step 5.
    //    4. The year is a leap year (it has 366 days).
    //    5. The year is not a leap year (it has 365 days).

    if (trueYear % 4 == 0)
    {
        if (trueYear % 100 == 0)
        {
            if (trueYear % 400 == 0)
            {
                // year is evenly divisible by 4, 100, and 400
                // leap year
                return true;
            }
            else
            {
                // year is evenly divisible by 4, and 100 but NOT 400
                // NOT a leap year
                return false;
            }
        }
        else
        {
            // year is evenly divisible by 4 but not evenly divisible by 100
            // leap year
            return true;
        }
    }
    else
    {
        // year is not evenly divisible by 4
        // NOT a leap year
        return false;
    }
}

// Time2a DOWDay Structure
void parseIec104Time2aDowday(const Iec104Cp56Time2aType* sevenOctetBinaryTime)
{
    // Day of week will always be between 0 and 7 since the field is only 3 bits
    // make sure month is at least 1 and no more than 12
    if (sevenOctetBinaryTime->res3month.month >= IEC104_MONTH_JAN
        and sevenOctetBinaryTime->res3month.month <= IEC104_MONTH_DEC)
    {
        // do in depth datetime analysis
        if (sevenOctetBinaryTime->res3month.month == IEC104_MONTH_FEB)
        {
            // handle leap year first
            if (isLeapYear(sevenOctetBinaryTime->res4year.year))
            {
                if (sevenOctetBinaryTime->dowday.dayOfMonth > IEC104_MAX_DAYOFMONTH_FEB_LEAPYEAR)
                {
                    // "CP56Time2a Day of Month set outside of the allowable range for leap year
                    DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_DAY_OF_MONTH);
                }
            }
            else
            {
                if (sevenOctetBinaryTime->dowday.dayOfMonth > IEC104_MAX_DAYOFMONTH_FEB_NONLEAPYEAR)
                {
                    // CP56Time2a Day of Month set outside of the allowable range for non-leap year
                    DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_DAY_OF_MONTH);
                }
            }
            // handle all months with 30 days
        }
        else if (sevenOctetBinaryTime->res3month.month == IEC104_MONTH_APR
            or sevenOctetBinaryTime->res3month.month == IEC104_MONTH_JUN
            or sevenOctetBinaryTime->res3month.month == IEC104_MONTH_SEP
            or sevenOctetBinaryTime->res3month.month == IEC104_MONTH_NOV)
        {
            if (sevenOctetBinaryTime->dowday.dayOfMonth > IEC104_MAX_DAYOFMONTH_30)
            {
                // CP56Time2a Day of Month set outside of the allowable range for 30-day months
                DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_DAY_OF_MONTH);
            }

        }// months with 31 days cannot be over as the type isn't large enough
    }
    else
    {
        // error indicating that parsing couldn't finish
    }
}

// Time2a Res3Month Structure
void parseIec104Time2aRes3month(const Iec104Time2aRes3monthType* time2aRes3month)
{
    // ensure month is not over 12 (December)
    if (time2aRes3month->month < IEC104_MONTH_JAN or time2aRes3month->month > IEC104_MONTH_DEC)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_MONTH);
    }

    // provide an alert if the reserved field is used
    if (time2aRes3month->res3)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_MONTH);
    }
}

// Time2a Res4Year Structure
void parseIec104Time2aRes4year(const Iec104Time2aRes4yearType* time2aRes4year)
{
    // ensure the year isn't before 1970 or after 2027
    // the year field is treated as an offset from the year 1900
    // so 1970 == 70 and 2027 == 127
    // 2027 was chosen as an end date as the time2aRes4year->year field is only 7 bits
    if ((int) time2aRes4year->year < IEC104_TIME2ARES4YEAR_1970)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_YEAR);
    }

    // provide an alert if the reserved field is used
    if (time2aRes4year->res4)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_YEAR);
    }
}

// CP56Time2a Structure
void parseIec104Cp56Time2a(const Iec104Cp56Time2aType* sevenOctetBinaryTime)
{
    // Nothing worth alerting on directly here

    parseIec104Time2aMilliseconds(&sevenOctetBinaryTime->milliseconds);
    parseIec104Time2aIvresminute(&sevenOctetBinaryTime->ivresminute);
    parseIec104Time2aSures2hour(&sevenOctetBinaryTime->sures2hour);
    parseIec104Time2aDowday(sevenOctetBinaryTime); // need to pass the entire time struct for full error checking
    parseIec104Time2aRes3month(&sevenOctetBinaryTime->res3month);
    parseIec104Time2aRes4year(&sevenOctetBinaryTime->res4year);
}

// Cp24Time2a Structure
void parseIec104Cp24Time2a(const Iec104Cp24Time2aType* threeOctetBinaryTime)
{
    // Nothing worth alerting on directly here

    parseIec104Time2aMilliseconds(&threeOctetBinaryTime->milliseconds);
    parseIec104Time2aIvresminute(&threeOctetBinaryTime->ivresminute);
}

// Cp16Time2a Structure
void parseIec104Cp16Time2a(const Iec104Cp16Time2aType* cp16Time2a)
{
    // Nothing worth alerting on directly here

    parseIec104Time2aMilliseconds(&cp16Time2a->milliseconds);
}

// NOF: Name of File Structure
void parseIec104Nof(const Iec104NofType* nof)
{
    // Nothing worth alerting on directly here

    if (!nof)
    {
        // error indicating that parsing couldn't finish
    }
}

// NOS: Name of Section Structure
void parseIec104Nos(const Iec104NosType* nos)
{
    // Nothing worth alerting on directly here

    if (!nos)
    {
        // error indicating that parsing couldn't finish
    }
}

// LOF: Length of File or Section Structure
void parseIec104Lof(const Iec104LofType* lof)
{
    // maybe a rule checking if length of file is greater than amount of data
    //  It appears that the length field here is an indicator for other messages actually containing the
    //  file data so detection may be better via plaintext rules with flowbits if desired

    if (!lof)
    {
        // error indicating that parsing couldn't finish
    }
}

// LOS: Length of Segment Structure
bool parseIec104Los(const Iec104LosType* los, uint16_t apduSize)
{
    // flag to prevent debug parsing of the segments when an alert is thrown
    // doing this via a flag so that the debug messages for the LOS field still print
    bool losValid = true;

    // number of bytes counted in the length field before the LOS field
    uint16_t losPrecedingBytes = 0x11;

    // a segment length of zero is not expected
    if (los->lengthOfSegment == 0)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_NULL_LOS_VALUE);
        losValid = false;
    }
    // since the los value indicates the number of octets in the segment and it is only used
    // in ASDU types that cannot have multiple number of items, the los value times 8 should
    // always equal the remaining number of bytes in the message
    // we can calculate this number by taking the apduSize (which has been checked for tampering
    // earlier) and subtracting the number of bytes preceding the los field (0x11)
    else if (los->lengthOfSegment != (apduSize - losPrecedingBytes))
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_INVALID_LOS_VALUE);
        losValid = false;
    }

    return losValid;
}

// CHS: Checksum Structure
void parseIec104Chs(const Iec104ChsType* chs)
{
    // Nothing worth alerting on directly here

    if (!chs)
    {
        // error indicating that parsing couldn't finish
    }
}

// SOF: Status of File Structure
void parseIec104Sof(const Iec104SofType* sof)
{
    // provide an alert if the reserved field is used
    if (sof->sofStatus >= IEC104_SOF_STATUS_RES1)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_SOF);
    }
}

// QOS: Qualifier of Set Point Command Structure
void parseIec104Qos(const Iec104QosType* qos)
{
    // provide an alert if the reserved field is used
    if (qos->ql >= IEC104_QOS_QL_RES1)
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_RESERVED_QOS);
    }
}

// SCD: Status + Status Change Detection Structure
void parseIec104Scd(const Iec104ScdType* scd)
{
    // Nothing worth alerting on directly here

    if (!scd)
    {
        // error indicating that parsing couldn't finish
    }
}

// TSC: Test Sequence Counter
void parseIec104Tsc(const Iec104TscType* tsc)
{
    // Nothing worth alerting on directly here

    if (!tsc)
    {
        // error indicating that parsing couldn't finish
    }
}

// Segment: Segment type
void parseIec104Segment(const Iec104SegmentType* segment)
{
    // Nothing worth alerting on directly here

    if (!segment)
    {
        // error indicating that parsing couldn't finish
    }
}

