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

// iec104_parse_apdu.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef IEC104_PARSE_APCI_H
#define IEC104_PARSE_APCI_H

#include <cstdint>

void parseIec104ApciU(const struct Iec104ApciU* apci);
void parseIec104ApciS(const struct Iec104ApciS* apci);
void parseIec104ApciI(const struct Iec104ApciI* apci);


#define IEC104_ERROR -1
#define IEC104_START_BYTE 0x68
#define IEC104_APCI_HDR_LEN 2 // accounts for Start and Length
#define IEC104_APCI_TYPE_U_LEN 4
#define IEC104_APCI_TYPE_S_LEN 4
#define IEC104_APCI_TYPE_I_MIN_LEN 12
#define IEC104_APCI_TYPE_I_HDR_LEN 6
#define IEC104_CTX_NOT_ALLOWED 0
#define IEC104_CTX_ALLOWED 1


//
//
// Enums
//
//

// Definition for the different APCI headers
// This allows us to make determinations on how to handle the fields following the first 1-2 bits
enum ApciTypeEnum
{
    IEC104_NO_APCI     = -1,
    IEC104_APCI_TYPE_I = 0,
    IEC104_APCI_TYPE_S = 1,
    IEC104_APCI_TYPE_U = 2,
};

enum AsduTypeEnum
{
    IEC104_NO_ASDU         =  0,     // placeholder for an error case
    IEC104_ASDU_M_SP_NA_1  =  1,     // Single-point information
    IEC104_ASDU_M_SP_TA_1  =  2,     // Single-point information with time tag
    IEC104_ASDU_M_DP_NA_1  =  3,     // Double-point information
    IEC104_ASDU_M_DP_TA_1  =  4,     // Double-point information with time tag
    IEC104_ASDU_M_ST_NA_1  =  5,     // Step position information
    IEC104_ASDU_M_ST_TA_1  =  6,     // Step position information with time tag
    IEC104_ASDU_M_BO_NA_1  =  7,     // Bitstring of 32 bit
    IEC104_ASDU_M_BO_TA_1  =  8,     // Bitstring of 32 bit with time tag
    IEC104_ASDU_M_ME_NA_1  =  9,     // Measured value, normalized value
    IEC104_ASDU_M_ME_TA_1  =  10,    // Measured value, normalized value with time tag
    IEC104_ASDU_M_ME_NB_1  =  11,    // Measured value, scaled value
    IEC104_ASDU_M_ME_TB_1  =  12,    // Measured value, scaled value wit time tag
    IEC104_ASDU_M_ME_NC_1  =  13,    // Measured value, short floating point number
    IEC104_ASDU_M_ME_TC_1  =  14,    // Measured value, short floating point number with time tag
    IEC104_ASDU_M_IT_NA_1  =  15,    // Integrated totals
    IEC104_ASDU_M_IT_TA_1  =  16,    // Integrated totals with time tag
    IEC104_ASDU_M_EP_TA_1  =  17,    // Event of protection equipment with time tag
    IEC104_ASDU_M_EP_TB_1  =  18,    // Packed start events of protection equipment with time tag
    IEC104_ASDU_M_EP_TC_1  =  19,    // Packed output circuit information of protection equipment with time tag
    IEC104_ASDU_M_PS_NA_1  =  20,    // Packed single point information with status change detection
    IEC104_ASDU_M_ME_ND_1  =  21,    // Measured value, normalized value without quality descriptor
    // 22-29 reserved
    IEC104_ASDU_M_SP_TB_1  =  30,    // Single-point information with time tag CP56Time2a
    IEC104_ASDU_M_DP_TB_1  =  31,    // Double-point information with time tag CP56Time2a
    IEC104_ASDU_M_ST_TB_1  =  32,    // Step position information with time tag CP56Time2a
    IEC104_ASDU_M_BO_TB_1  =  33,    // Bitstring of 32 bit with time tag CP56Time2a
    IEC104_ASDU_M_ME_TD_1  =  34,    // Measured value, normalized value with time tag CP56Time2a
    IEC104_ASDU_M_ME_TE_1  =  35,    // Measured value, scaled value with time tag CP56Time2a
    IEC104_ASDU_M_ME_TF_1  =  36,    // Measured value, short floating point number with time tag CP56Time2a
    IEC104_ASDU_M_IT_TB_1  =  37,    // Integrated totals with time tag CP56Time2a
    IEC104_ASDU_M_EP_TD_1  =  38,    // Event of protection equipment with time tag CP56Time2a
    IEC104_ASDU_M_EP_TE_1  =  39,    // Packed start events of protection equipment with time tag CP56Time2a
    IEC104_ASDU_M_EP_TF_1  =  40,    // Packed output circuit information of protection equipment with time tag CP56Time2a
    // 41-44 reserved
    IEC104_ASDU_C_SC_NA_1  =  45,    // Single command
    IEC104_ASDU_C_DC_NA_1  =  46,    // Double command
    IEC104_ASDU_C_RC_NA_1  =  47,    // Regulating step command
    IEC104_ASDU_C_SE_NA_1  =  48,    // Set-point Command, normalized value
    IEC104_ASDU_C_SE_NB_1  =  49,    // Set-point Command, scaled value
    IEC104_ASDU_C_SE_NC_1  =  50,    // Set-point Command, short floating point number
    IEC104_ASDU_C_BO_NA_1  =  51,    // Bitstring 32 bit command
    // 52-57 reserved
    IEC104_ASDU_C_SC_TA_1  =  58,    // Single command with time tag CP56Time2a
    IEC104_ASDU_C_DC_TA_1  =  59,    // Double command with time tag CP56Time2a
    IEC104_ASDU_C_RC_TA_1  =  60,    // Regulating step command with time tag CP56Time2a
    IEC104_ASDU_C_SE_TA_1  =  61,    // Set-point command with time tag CP56Time2a, normalized value
    IEC104_ASDU_C_SE_TB_1  =  62,    // Set-point command with time tag CP56Time2a, scaled value
    IEC104_ASDU_C_SE_TC_1  =  63,    // Set-point command with time tag CP56Time2a, short floating point number
    IEC104_ASDU_C_BO_TA_1  =  64,    // Bitstring of 32 bit with time tag CP56Time2a
    // 65-69 reserved
    IEC104_ASDU_M_EI_NA_1  =  70,    // End of initialization
    // 71-99 reserved
    IEC104_ASDU_C_IC_NA_1  =  100,   // Interrogation command
    IEC104_ASDU_C_CI_NA_1  =  101,   // Counter interrogation command
    IEC104_ASDU_C_RD_NA_1  =  102,   // Read command
    IEC104_ASDU_C_CS_NA_1  =  103,   // Clock synchronization command
    IEC104_ASDU_C_TS_NA_1  =  104,   // Test command
    IEC104_ASDU_C_RP_NA_1  =  105,   // Reset process command
    IEC104_ASDU_C_CD_NA_1  =  106,   // Delay acquisition command
    IEC104_ASDU_C_TS_TA_1  =  107,   // Test command with time tag CP56Time2a
    // 108-109 reserved
    IEC104_ASDU_P_ME_NA_1  =  110,   // Parameter of measured values, normalized value
    IEC104_ASDU_P_ME_NB_1  =  111,   // Parameter of measured values, scaled value
    IEC104_ASDU_P_ME_NC_1  =  112,   // Parameter of measured values, short floating point number
    IEC104_ASDU_P_AC_NA_1  =  113,   // Parameter activation
    // 114-119 reserved
    IEC104_ASDU_F_FR_NA_1  =  120,   // File ready
    IEC104_ASDU_F_SR_NA_1  =  121,   // Section ready
    IEC104_ASDU_F_SC_NA_1  =  122,   // Call directory, select file, call file, call section
    IEC104_ASDU_F_LS_NA_1  =  123,   // Last section, last segment
    IEC104_ASDU_F_AF_NA_1  =  124,   // ACK file, ACK section
    IEC104_ASDU_F_SG_NA_1  =  125,   // Single information object
    IEC104_ASDU_F_DR_TA_1  =  126,   // Sequence of information elements in a single information object
    IEC104_ASDU_F_SC_NB_1  =  127,   // QueryLog – Request archive file
    // 128-256 reserved
};

// Definition for the different transmission cause codes
enum CauseOfTransmissionEnum
{
    IEC104_CAUSE_TX_NOT_USED                      = 0,     // not used
    IEC104_CAUSE_TX_PER_CYC                       = 1,     // periodic, cyclic
    IEC104_CAUSE_TX_BACK                          = 2,     // background scan3
    IEC104_CAUSE_TX_SPONT                         = 3,     // spontaneous
    IEC104_CAUSE_TX_INIT                           = 4,     // initialized
    IEC104_CAUSE_TX_REQ                            = 5,     // request or requested
    IEC104_CAUSE_TX_ACT                           = 6,     // activation
    IEC104_CAUSE_TX_ACTCON                        = 7,     // activation confirmation
    IEC104_CAUSE_TX_DEACT                         = 8,     // deactivation
    IEC104_CAUSE_TX_DEACTCON                      = 9,     // deactivation confirmation
    IEC104_CAUSE_TX_ACTTERM                       = 10,    // activation termination
    IEC104_CAUSE_TX_RETREM                        = 11,    // return information caused by a remote command
    IEC104_CAUSE_TX_RETLOC                         = 12,    // return information caused by a local command
    IEC104_CAUSE_TX_FILE                          = 13,    // file transfer
    IEC104_CAUSE_TX_RES14                         = 14,    // 14-19 reserved
    IEC104_CAUSE_TX_RES15                         = 15,    // 14-19 reserved
    IEC104_CAUSE_TX_RES16                         = 16,    // 14-19 reserved
    IEC104_CAUSE_TX_RES17                         = 17,    // 14-19 reserved
    IEC104_CAUSE_TX_RES18                         = 18,    // 14-19 reserved
    IEC104_CAUSE_TX_RES19                         = 19,    // 14-19 reserved
    IEC104_CAUSE_TX_INROGEN                       = 20,    // interrogated by station interrogation
    IEC104_CAUSE_TX_INRO1                         = 21,    // interrogated by group 1 interrogation
    IEC104_CAUSE_TX_INRO2                         = 22,    // interrogated by group 2 interrogation
    IEC104_CAUSE_TX_INRO3                         = 23,    // interrogated by group 3 interrogation
    IEC104_CAUSE_TX_INRO4                         = 24,    // interrogated by group 4 interrogation
    IEC104_CAUSE_TX_INRO5                         = 25,    // interrogated by group 5 interrogation
    IEC104_CAUSE_TX_INRO6                         = 26,    // interrogated by group 6 interrogation
    IEC104_CAUSE_TX_INRO7                         = 27,    // interrogated by group 7 interrogation
    IEC104_CAUSE_TX_INRO8                         = 28,    // interrogated by group 8 interrogation
    IEC104_CAUSE_TX_INRO9                         = 29,    // interrogated by group 9 interrogation
    IEC104_CAUSE_TX_INRO10                        = 30,    // interrogated by group 10 interrogation
    IEC104_CAUSE_TX_INRO11                        = 31,    // interrogated by group 11 interrogation
    IEC104_CAUSE_TX_INRO12                        = 32,    // interrogated by group 12 interrogation
    IEC104_CAUSE_TX_INRO13                        = 33,    // interrogated by group 13 interrogation
    IEC104_CAUSE_TX_INRO14                        = 34,    // interrogated by group 14 interrogation
    IEC104_CAUSE_TX_INRO15                        = 35,    // interrogated by group 15 interrogation
    IEC104_CAUSE_TX_INRO16                        = 36,    // interrogated by group 16 interrogation
    IEC104_CAUSE_TX_REQCOGEN                      = 37,    // requested by general counter request
    IEC104_CAUSE_TX_REQCO1                        = 38,    // requested by group 1 counter request
    IEC104_CAUSE_TX_REQCO2                        = 39,    // requested by group 2 counter request
    IEC104_CAUSE_TX_REQCO3                        = 40,    // requested by group 3 counter request
    IEC104_CAUSE_TX_REQCO4                        = 41,    // requested by group 4 counter request
    IEC104_CAUSE_TX_RES42                         = 42,    // 42-43 reserved
    IEC104_CAUSE_TX_RES43                         = 43,    // 42-43 reserved
    IEC104_CAUSE_TX_UNKNOWN_TYPE_ID               = 44,    // unknown type identification
    IEC104_CAUSE_TX_UNKNOWN_CAUSE_OF_TX           = 45,    // unknown cause of transmission
    IEC104_CAUSE_TX_UNKNOWN_COMMON_ADDR_OF_ASDU   = 46,    // unknown common address of ASDU
    IEC104_CAUSE_TX_UNKNOWN_IOA                   = 47,    // unknown information object address
    IEC104_CAUSE_TX_RES48                         = 48,    // 48-63 reserved
    IEC104_CAUSE_TX_RES49                         = 49,    // 48-63 reserved
    IEC104_CAUSE_TX_RES50                         = 50,    // 48-63 reserved
    IEC104_CAUSE_TX_RES51                         = 51,    // 48-63 reserved
    IEC104_CAUSE_TX_RES52                         = 52,    // 48-63 reserved
    IEC104_CAUSE_TX_RES53                         = 53,    // 48-63 reserved
    IEC104_CAUSE_TX_RES54                         = 54,    // 48-63 reserved
    IEC104_CAUSE_TX_RES55                         = 55,    // 48-63 reserved
    IEC104_CAUSE_TX_RES56                         = 56,    // 48-63 reserved
    IEC104_CAUSE_TX_RES57                         = 57,    // 48-63 reserved
    IEC104_CAUSE_TX_RES58                         = 58,    // 48-63 reserved
    IEC104_CAUSE_TX_RES59                         = 59,    // 48-63 reserved
    IEC104_CAUSE_TX_RES60                         = 60,    // 48-63 reserved
    IEC104_CAUSE_TX_RES61                         = 61,    // 48-63 reserved
    IEC104_CAUSE_TX_RES62                         = 62,    // 48-63 reserved
    IEC104_CAUSE_TX_RES63                         = 63,    // 48-63 reserved
};

enum StructureQualifierEnum
{
    IEC104_SQ_FALSE  = 0,
    IEC104_SQ_TRUE   = 1,
};




//
//
// Structs
//
//

//
// Generic structs
//

// struct Iec104To help determine what type of APCI is in use
struct Iec104GenericApci
{
    uint8_t start;
    uint8_t length;
    uint8_t apciTypeMajor : 1;
    uint8_t apciTypeMinor : 1;
    uint8_t reserved : 6;
}__attribute__((packed));


//
// ASDU Information Object Structs
//

struct Iec104VariableStructureQualifierType
{
    uint8_t numberOfElements : 7;
    uint8_t sq : 1;
}__attribute__((packed));

// This structure does not require the OA, but it seems to be used in all traffic seen so far
struct Iec104CauseOfTransmissionType
{
    uint8_t causeOfTransmission : 6;
    uint8_t pn : 1;
    uint8_t test : 1;
    uint8_t oa;
}__attribute__((packed));

// COI: Cause of Initialization Structure
struct Iec104CoiType
{
    uint8_t ui : 7;
    uint8_t bs : 1;
}__attribute__((packed));

// QOI: Qualifier of Interrogation Structure
struct Iec104QoiType
{
    uint8_t qoi;
}__attribute__((packed));

// QCC: Qualifier of Counter Interrogation Command Structure
struct Iec104QccType
{
    uint8_t rqt : 6;
    uint8_t frz : 2;
}__attribute__((packed));

// QPM: Qualifier of Parameter of Measured Values Structure
struct Iec104QpmType
{
    uint8_t kpa : 6;
    uint8_t lpc : 1;
    uint8_t pop : 1;
}__attribute__((packed));

// QPA: Qualifier of Parameter Activation Structure
struct Iec104QpaType
{
    uint8_t qpa;
}__attribute__((packed));

// QOC: Qualifier of Command Structure
// This doesn't add up to 8, but that is expected
// This struct gets used in fields that have 2 preceding bits
struct Iec104QocType
{
    uint8_t qu : 5;
    uint8_t se : 1;
}__attribute__((packed));

// QRP: Qualifier of Reset Process Structure
struct Iec104QrpType
{
    uint8_t qrp;
}__attribute__((packed));

// FRQ: File Ready Qualifier Structure
struct Iec104FrqType
{
    uint8_t ui : 7;
    uint8_t bs : 1;
}__attribute__((packed));

// SRQ: Section Ready Qualifier Structure
struct Iec104SrqType
{
    uint8_t ui : 7;
    uint8_t bs : 1;
}__attribute__((packed));

// SCQ: Select and Call Qualifier Structure
struct Iec104ScqType
{
    uint8_t ui1 : 4;
    uint8_t ui2 : 4;
}__attribute__((packed));

// LSQ: Last Section or Segment Qualifier Structure
struct Iec104LsqType
{
    uint8_t lsq;
}__attribute__((packed));

// AFQ: Acknowledge File or Section Qualifier Structure
struct Iec104AfqType
{
    uint8_t ui1 : 4;
    uint8_t ui2 : 4;
}__attribute__((packed));

// Common Address of ASDU Structure
// This structure does not require the high octet, but it seems to be
//  used in all traffic seen so far
struct Iec104CommonAddressOfAsduType
{
    uint16_t commonAddress;
}__attribute__((packed));

// Information Object Address One Octet Structure
struct Iec104InformationObjectAddressOneOctetType
{
    uint8_t informationObjectAddress;
}__attribute__((packed));

// Information Object Address Two Octet Structure
struct Iec104InformationObjectAddressTwoOctetType
{
    uint8_t informationObjectAddress[2];
}__attribute__((packed));

// Information Object Address Three Octet Structure
struct Iec104InformationObjectAddressThreeOctetType
{
    uint8_t informationObjectAddress[3];
}__attribute__((packed));

// SIQ: Single Point Information with Quality Descriptor Structure
struct Iec104SiqType
{
    uint8_t spi : 1;
    uint8_t reserved : 3;
    uint8_t bl : 1;
    uint8_t sb : 1;
    uint8_t nt : 1;
    uint8_t iv : 1;
}__attribute__((packed));

// DIQ: Double Point Information with Quality Descriptor Structure
struct Iec104DiqType
{
    uint8_t dpi : 2;
    uint8_t reserved : 2;
    uint8_t bl : 1;
    uint8_t sb : 1;
    uint8_t nt : 1;
    uint8_t iv : 1;
}__attribute__((packed));

// QDS: Quality Descriptor Structure
struct Iec104QdsType
{
    uint8_t ov : 1;
    uint8_t reserved : 3;
    uint8_t bl : 1;
    uint8_t sb : 1;
    uint8_t nt : 1;
    uint8_t iv : 1;
}__attribute__((packed));

// QDP: Quality Descriptor for Events of Protection Equipment Structure
struct Iec104QdpType
{
    uint8_t reserved : 3;
    uint8_t ei : 1;
    uint8_t bl : 1;
    uint8_t sb : 1;
    uint8_t nt : 1;
    uint8_t iv : 1;
}__attribute__((packed));

// VTI: Value with Transient State Indication Structure
struct Iec104VtiType
{
    uint8_t value : 7;
    uint8_t t : 1;
}__attribute__((packed));

// NVA: Normalized Value Structure
struct Iec104NvaType
{
    uint16_t value;
}__attribute__((packed));

// SVA: Scaled Value Structure
struct Iec104SvaType
{
    uint16_t value;
}__attribute__((packed));

// IEEE_STD_754: Short Floating Point Number Structure
struct Iec104IeeeStd754Type
{
    uint32_t ieeeStd754;
}__attribute__((packed));

// BCR: Binary Counter Reading Structure
struct Iec104BcrType
{
    uint32_t value;
    uint8_t sequenceNumber : 5;
    uint8_t cy : 1;
    uint8_t ca : 1;
    uint8_t iv : 1;
}__attribute__((packed));

// SEP: Single Event of Protection Equipment Structure
struct Iec104SepType
{
    uint8_t es : 2;
    uint8_t reserved : 1;
    uint8_t ei : 1;
    uint8_t bl : 1;
    uint8_t sb : 1;
    uint8_t nt : 1;
    uint8_t iv : 1;
}__attribute__((packed));

// SPE: Start Event of Protection Equipment Structure
struct Iec104SpeType
{
    uint8_t gs : 1;
    uint8_t sl1 : 1;
    uint8_t sl2 : 1;
    uint8_t sl3 : 1;
    uint8_t sie : 1;
    uint8_t srd : 1;
    uint8_t reserved : 2;
}__attribute__((packed));

// OCI: Output Circuit Information Structure
struct Iec104OciType
{
    uint8_t gc : 1;
    uint8_t cl1 : 1;
    uint8_t cl2 : 1;
    uint8_t cl3 : 1;
    uint8_t reserved : 4;
}__attribute__((packed));

// BSI: Binary State Information Structure
struct Iec104BsiType
{
    uint32_t bitstring;
}__attribute__((packed));

// FBP: Fixed Test Bit Pattern Structure
struct Iec104FbpType
{
    uint16_t fixedTestBitPattern;
}__attribute__((packed));

// SCO: Single Command Structure
struct Iec104ScoType
{
    uint8_t scs : 1;
    uint8_t reserved : 1;
    uint8_t qu : 5;
    uint8_t se : 1;
}__attribute__((packed));

// DCO: Double Command Structure
struct Iec104DcoType
{
    uint8_t dcs : 2;
    uint8_t qu : 5;
    uint8_t se : 1;
}__attribute__((packed));

// RCO: Regulating Step Command Structure
struct Iec104RcoType
{
    uint8_t rcs : 2;
    uint8_t qu : 5;
    uint8_t se : 1;
}__attribute__((packed));

// Time2a Milliseconds Structure
struct Iec104Time2aMillisecondsType
{
    uint16_t milliseconds;
}__attribute__((packed));

// Time2a IVResMinute Structure
struct Iec104Time2aIvresminuteType
{
    uint8_t minutes : 6;
    uint8_t res : 1;
    uint8_t iv : 1;
}__attribute__((packed));

// Time2a SURes2Hour Structure
struct Iec104Time2aSures2hourType
{
    uint8_t hours : 5;
    uint8_t res2 : 2;
    uint8_t su : 1;
}__attribute__((packed));

// Time2a DOWDay Structure
struct Iec104Time2aDowdayType
{
    uint8_t dayOfMonth : 5;
    uint8_t dayOfWeek : 3;
}__attribute__((packed));

// Time2a Res3Month Structure
struct Iec104Time2aRes3monthType
{
    uint8_t month : 4;
    uint8_t res3 : 4;
}__attribute__((packed));

// Time2a Res4Year Structure
struct Iec104Time2aRes4yearType
{
    uint8_t year : 7;
    uint8_t res4 : 1;
}__attribute__((packed));

// CP56Time2a Structure
struct Iec104Cp56Time2aType
{
    Iec104Time2aMillisecondsType milliseconds;
    Iec104Time2aIvresminuteType ivresminute;
    Iec104Time2aSures2hourType sures2hour;
    Iec104Time2aDowdayType dowday;
    Iec104Time2aRes3monthType res3month;
    Iec104Time2aRes4yearType res4year;
}__attribute__((packed));

// Cp24Time2a Structure
struct Iec104Cp24Time2aType
{
    Iec104Time2aMillisecondsType milliseconds;
    Iec104Time2aIvresminuteType ivresminute;
}__attribute__((packed));

// Cp16Time2a Structure
struct Iec104Cp16Time2aType
{
    Iec104Time2aMillisecondsType milliseconds;
}__attribute__((packed));

// NOF: Name of File Structure
struct Iec104NofType
{
    uint16_t nameOfFile;
}__attribute__((packed));

// NOS: Name of Section Structure
struct Iec104NosType
{
    uint8_t nameOfSection;
}__attribute__((packed));

// LOF: Length of File or Section Structure
struct Iec104LofType
{
    uint8_t lengthOfFile[3];
}__attribute__((packed));

// LOS: Length of Segment Structure
struct Iec104LosType
{
    uint8_t lengthOfSegment;
}__attribute__((packed));

// CHS: Checksum Structure
struct Iec104ChsType
{
    uint8_t chs;
}__attribute__((packed));

// SOF: Status of File Structure
// need to prepend `sof` tag on here since `for` is a reserved word
// doing it for the rest for consistency
struct Iec104SofType
{
    uint8_t sofStatus : 5;
    uint8_t sofLfd : 1;
    uint8_t sofFor : 1;
    uint8_t sofFa : 1;
}__attribute__((packed));

// QOS: Qualifier of Set Point Command Structure
struct Iec104QosType
{
    uint8_t ql : 7;
    uint8_t se : 1;
}__attribute__((packed));

// SCD: Status + Status Change Detection Structure
struct Iec104ScdType
{
    uint16_t st;
    uint16_t cd;
}__attribute__((packed));

// TSC: Test Sequence Counter
struct Iec104TscType
{
    uint16_t tsc;
}__attribute__((packed));

// Segment: Segment type
struct Iec104SegmentType
{
    uint8_t segment;
}__attribute__((packed));

// Information Element
struct Iec104InformationElementType
{
    Iec104NofType nameOfFileOrSubdirectory;
    Iec104LofType lengthOfFile;
    Iec104SofType sof;
    Iec104Cp56Time2aType creationTimeOfFile;
}__attribute__((packed));


//
//
// ASDU structs
//
//

//
// ASDUs for process information in monitor direction
//

// ASDU Type M_SP_NA_1
// Ident 1
// Single-point information

struct Iec104M_SP_NA_1_IO_Subgroup
{
    Iec104SiqType siq;
}__attribute__((packed));

struct Iec104M_SP_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_SP_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_SP_TA_1
// Ident 2
// Single-point information with time tag

struct Iec104M_SP_TA_1_IO_Subgroup
{
    Iec104SiqType siq;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_SP_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_SP_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_DP_NA_1
// Ident 3
// Double-point information

struct Iec104M_DP_NA_1_IO_Subgroup
{
    Iec104DiqType diq;
}__attribute__((packed));

struct Iec104M_DP_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_DP_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_DP_TA_1
// Ident 4
// Double-point information with time tag

struct Iec104M_DP_TA_1_IO_Subgroup
{
    Iec104DiqType diq;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_DP_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_DP_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ST_NA_1
// Ident 5
// Step position information

struct Iec104M_ST_NA_1_IO_Subgroup
{
    Iec104VtiType vti;
    Iec104QdsType qds;
}__attribute__((packed));

struct Iec104M_ST_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ST_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ST_TA_1
// Ident 6
// Step position information with time tag

struct Iec104M_ST_TA_1_IO_Subgroup
{
    Iec104VtiType vti;
    Iec104QdsType qds;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ST_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ST_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_BO_NA_1
// Ident 7
// Bitstring of 32 bit

struct Iec104M_BO_NA_1_IO_Subgroup
{
    Iec104BsiType bsi;
    Iec104QdsType qds;
}__attribute__((packed));

struct Iec104M_BO_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_BO_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_BO_TA_1
// Ident 8
// Bitstring of 32 bit with time tag

struct Iec104M_BO_TA_1_IO_Subgroup
{
    Iec104BsiType bsi;
    Iec104QdsType qds;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_BO_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_BO_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_NA_1
// Ident 9
// Measured value, normalized value

struct Iec104M_ME_NA_1_IO_Subgroup
{
    Iec104NvaType nva;
    Iec104QdsType qds;
}__attribute__((packed));

struct Iec104M_ME_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_TA_1
// Ident 10
// Measured value, normalized value with time tag

struct Iec104M_ME_TA_1_IO_Subgroup
{
    Iec104NvaType nva;
    Iec104QdsType qds;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ME_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_NB_1
// Ident 11
// Measured value, scaled value

struct Iec104M_ME_NB_1_IO_Subgroup
{
    Iec104SvaType sva;
    Iec104QdsType qds;
}__attribute__((packed));

struct Iec104M_ME_NB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_NB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_TB_1
// Ident 12
// Measured value, scaled value wit time tag

struct Iec104M_ME_TB_1_IO_Subgroup
{
    Iec104SvaType sva;
    Iec104QdsType qds;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ME_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_NC_1
// Ident 13
// Measured value, short floating point number

struct Iec104M_ME_NC_1_IO_Subgroup
{
    Iec104IeeeStd754Type ieeeStd754;
    Iec104QdsType qds;
}__attribute__((packed));

struct Iec104M_ME_NC_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_NC_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_TC_1
// Ident 14
// Measured value, short floating point number with time tag

struct Iec104M_ME_TC_1_IO_Subgroup
{
    Iec104IeeeStd754Type ieeeStd754;
    Iec104QdsType qds;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ME_TC_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_TC_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_IT_NA_1
// Ident 15
// Integrated totals

struct Iec104M_IT_NA_1_IO_Subgroup
{
    Iec104BcrType bcr;
}__attribute__((packed));

struct Iec104M_IT_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_IT_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_IT_TA_1
// Ident 16
// Integrated totals with time tag

struct Iec104M_IT_TA_1_IO_Subgroup
{
    Iec104BcrType bcr;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_IT_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_IT_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_EP_TA_1
// Ident 17
// Event of protection equipment with time tag

struct Iec104M_EP_TA_1_IO_Subgroup
{
    Iec104SepType sep;
    Iec104Cp16Time2aType elapsedTime;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_EP_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_EP_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_EP_TB_1
// Ident 18
// Packed start events of protection equipment with time tag

struct Iec104M_EP_TB_1_IO_Subgroup
{
    Iec104SpeType spe;
    Iec104QdpType qdp;
    Iec104Cp16Time2aType relayDurationTime;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_EP_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_EP_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_EP_TC_1
// Ident 19
// Packed output circuit information of protection equipment with time tag

struct Iec104M_EP_TC_1_IO_Subgroup
{
    Iec104OciType oci;
    Iec104QdpType qdp;
    Iec104Cp16Time2aType relayOperatingTime;
    Iec104Cp24Time2aType threeOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_EP_TC_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_EP_TC_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_PS_NA_1
// Ident 20
// Packed single point information with status change detection

struct Iec104M_PS_NA_1_IO_Subgroup
{
    Iec104ScdType scd;
    Iec104QdsType qds;
}__attribute__((packed));

struct Iec104M_PS_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_PS_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_ND_1
// Ident 21
// Measured value, normalized value without quality descriptor

struct Iec104M_ME_ND_1_IO_Subgroup
{
    Iec104NvaType nva;
}__attribute__((packed));

struct Iec104M_ME_ND_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_ND_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_SP_TB_1
// Ident 30
// Single-point information with time tag CP56Time2a

struct Iec104M_SP_TB_1_IO_Subgroup
{
    Iec104SiqType siq;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_SP_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_SP_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_DP_TB_1
// Ident 31
// Double-point information with time tag CP56Time2a

struct Iec104M_DP_TB_1_IO_Subgroup
{
    Iec104DiqType diq;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_DP_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_DP_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ST_TB_1
// Ident 32
// Step position information with time tag CP56Time2a

struct Iec104M_ST_TB_1_IO_Subgroup
{
    Iec104VtiType vti;
    Iec104QdsType qds;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ST_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ST_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_BO_TB_1
// Ident 33
// Bitstring of 32 bit with time tag CP56Time2a

struct Iec104M_BO_TB_1_IO_Subgroup
{
    Iec104BsiType bsi;
    Iec104QdsType qds;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_BO_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_BO_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_TD_1
// Ident 34
// Measured value, normalized value with time tag CP56Time2a

struct Iec104M_ME_TD_1_IO_Subgroup
{
    Iec104NvaType nva;
    Iec104QdsType qds;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ME_TD_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_TD_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_TE_1
// Ident 35
// Measured value, scaled value with time tag CP56Time2a

struct Iec104M_ME_TE_1_IO_Subgroup
{
    Iec104SvaType sva;
    Iec104QdsType qds;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ME_TE_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_TE_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_ME_TF_1
// Ident 36
// Measured value, short floating point number with time tag CP56Time2a

struct Iec104M_ME_TF_1_IO_Subgroup
{
    Iec104IeeeStd754Type ieeeStd754;
    Iec104QdsType qds;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_ME_TF_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_ME_TF_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_IT_TB_1
// Ident 37
// Integrated totals with time tag CP56Time2a

struct Iec104M_IT_TB_1_IO_Subgroup
{
    Iec104BcrType bcr;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_IT_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_IT_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_EP_TD_1
// Ident 38
// Event of protection equipment with time tag CP56Time2a

struct Iec104M_EP_TD_1_IO_Subgroup
{
    Iec104SepType sep;
    Iec104Cp16Time2aType elapsedTime;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_EP_TD_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_EP_TD_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_EP_TE_1
// Ident 39
// Packed start events of protection equipment with time tag CP56Time2a

struct Iec104M_EP_TE_1_IO_Subgroup
{
    Iec104SepType sep;
    Iec104QdpType qdp;
    Iec104Cp16Time2aType relayDurationTime;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_EP_TE_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_EP_TE_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type M_EP_TF_1
// Ident 40
// Packed output circuit information of protection equipment with time tag CP56Time2a

struct Iec104M_EP_TF_1_IO_Subgroup
{
    Iec104OciType oci;
    Iec104QdpType qdp;
    Iec104Cp16Time2aType relayDurationTime;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104M_EP_TF_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_EP_TF_1_IO_Subgroup subgroup;
}__attribute__((packed));



//
// ASDUs for process information in control direction
//

// ASDU Type C_SC_NA_1

struct Iec104C_SC_NA_1_IO_Subgroup
{
    Iec104ScoType sco;
}__attribute__((packed));

struct Iec104C_SC_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SC_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_DC_NA_1

struct Iec104C_DC_NA_1_IO_Subgroup
{
    Iec104DcoType dco;
}__attribute__((packed));

struct Iec104C_DC_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_DC_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_RC_NA_1

struct Iec104C_RC_NA_1_IO_Subgroup
{
    Iec104RcoType rco;
}__attribute__((packed));

struct Iec104C_RC_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_RC_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_SE_NA_1

struct Iec104C_SE_NA_1_IO_Subgroup
{
    Iec104NvaType nva;
    Iec104QosType qos;
}__attribute__((packed));

struct Iec104C_SE_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SE_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_SE_NB_1

struct Iec104C_SE_NB_1_IO_Subgroup
{
    Iec104SvaType sva;
    Iec104QosType qos;
}__attribute__((packed));

struct Iec104C_SE_NB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SE_NB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_SE_NC_1

struct Iec104C_SE_NC_1_IO_Subgroup
{
    Iec104IeeeStd754Type ieeeStd754;
    Iec104QosType qos;
}__attribute__((packed));

struct Iec104C_SE_NC_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SE_NC_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_BO_NA_1

struct Iec104C_BO_NA_1_IO_Subgroup
{
    Iec104BsiType bsi;
}__attribute__((packed));

struct Iec104C_BO_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_BO_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_SC_TA_1
// Ident 58
// Single command with time tag CP56Time2a
//   IEC-60870-5-104

struct Iec104C_SC_TA_1_IO_Subgroup
{
    Iec104ScoType sco;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_SC_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SC_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_DC_TA_1
// Ident 59
// Double command with time tag CP56Time2a
//   IEC-60870-5-104

struct Iec104C_DC_TA_1_IO_Subgroup
{
    Iec104DcoType dco;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_DC_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_DC_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_RC_TA_1
// Ident 60
// Regulating step command with time tag CP56Time2a
//   IEC-60870-5-104

struct Iec104C_RC_TA_1_IO_Subgroup
{
    Iec104RcoType rco;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_RC_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_RC_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_SE_TA_1
// Ident 61
// Set-point command with time tag CP56Time2a, normalized value
//   IEC-60870-5-104

struct Iec104C_SE_TA_1_IO_Subgroup
{
    Iec104NvaType nva;
    Iec104QosType qos;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_SE_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SE_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_SE_TB_1
// Ident 62
// Set-point command with time tag CP56Time2a, scaled value
//   IEC-60870-5-104

struct Iec104C_SE_TB_1_IO_Subgroup
{
    Iec104SvaType sva;
    Iec104QosType qos;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_SE_TB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SE_TB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_SE_TC_1
// Ident 63
// Set-point command with time tag CP56Time2a, short floating point number
//   IEC-60870-5-104

struct Iec104C_SE_TC_1_IO_Subgroup
{
    Iec104IeeeStd754Type ieeeStd754;
    Iec104QosType qos;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_SE_TC_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_SE_TC_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_BO_TA_1
// Ident 64
// Bitstring of 32 bit with time tag CP56Time2a
//   IEC-60870-5-104

struct Iec104C_BO_TA_1_IO_Subgroup
{
    Iec104BsiType bsi;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_BO_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_BO_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));



//
// ASDUs for system information in monitor direction
//

// ASDU Type M_EI_NA_1
// Ident 70
// End of initialization

struct Iec104M_EI_NA_1_IO_Subgroup
{
    Iec104CoiType coi;
}__attribute__((packed));

struct Iec104M_EI_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104M_EI_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));



//
// ASDUs for system information in control direction
//

// ASDU Type C_IC_NA_1
// Ident 100
// Interrogation command

struct Iec104C_IC_NA_1_IO_Subgroup
{
    Iec104QoiType qoi;
}__attribute__((packed));

struct Iec104C_IC_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_IC_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_CI_NA_1
// Ident 101
// Counter interrogation command

struct Iec104C_CI_NA_1_IO_Subgroup
{
    Iec104QccType qcc;
}__attribute__((packed));

struct Iec104C_CI_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_CI_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_RD_NA_1
// Ident 102
// Read command

struct Iec104C_RD_NA_1_IO_Subgroup
{
    // No subgroup for this type
}__attribute__((packed));

struct Iec104C_RD_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_RD_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_CS_NA_1
// Ident 103
// Clock synchronization command

struct Iec104C_CS_NA_1_IO_Subgroup
{
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_CS_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_CS_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_TS_NA_1
// Ident 104
// Test command

struct Iec104C_TS_NA_1_IO_Subgroup
{
    Iec104FbpType fbp;
}__attribute__((packed));

struct Iec104C_TS_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_TS_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_RP_NA_1
// Ident 105
// Reset process command

struct Iec104C_RP_NA_1_IO_Subgroup
{
    Iec104QrpType qrp;
}__attribute__((packed));

struct Iec104C_RP_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_RP_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_CD_NA_1
// Ident 106
// Delay acquisition command

struct Iec104C_CD_NA_1_IO_Subgroup
{
    Iec104Cp16Time2aType msUpToSeconds;
}__attribute__((packed));

struct Iec104C_CD_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_CD_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type C_TS_TA_1
// Ident 107
// Test command with time tag CP56Time2a
//   IEC-60870-5-104

struct Iec104C_TS_TA_1_IO_Subgroup
{
    Iec104TscType tsc;
    Iec104Cp56Time2aType sevenOctetBinaryTime;
}__attribute__((packed));

struct Iec104C_TS_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104C_TS_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));



//
// ASDUs for parameter in control direction
//

// ASDU Type P_ME_NA_1
// Ident 110
// Parameter of measured values, normalized value

struct Iec104P_ME_NA_1_IO_Subgroup
{
    Iec104NvaType nva;
    Iec104QpmType qpm;
}__attribute__((packed));

struct Iec104P_ME_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104P_ME_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type P_ME_NB_1
// Ident 111
// Parameter of measured values, scaled value

struct Iec104P_ME_NB_1_IO_Subgroup
{
    Iec104SvaType sva;
    Iec104QpmType qpm;
}__attribute__((packed));

struct Iec104P_ME_NB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104P_ME_NB_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type P_ME_NC_1
// Ident 112
// Parameter of measured values, short floating point number

struct Iec104P_ME_NC_1_IO_Subgroup
{
    Iec104IeeeStd754Type ieeeStd754;
    Iec104QpmType qpm;
}__attribute__((packed));

struct Iec104P_ME_NC_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104P_ME_NC_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type P_AC_NA_1
// Ident 113
// Parameter activation

struct Iec104P_AC_NA_1_IO_Subgroup
{
    Iec104QpaType qpa;
}__attribute__((packed));

struct Iec104P_AC_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104P_AC_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));



//
// ASDUs for file transfer
//

// ASDU Type F_FR_NA_1
// Ident 120
// File ready

struct Iec104F_FR_NA_1_IO_Subgroup
{
    Iec104NofType nameOfFile;
    Iec104LofType lengthOfFile;
    Iec104FrqType frq;
}__attribute__((packed));

struct Iec104F_FR_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_FR_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type F_SR_NA_1
// Ident 121
// Section ready

struct Iec104F_SR_NA_1_IO_Subgroup
{
    Iec104NofType nameOfFile;
    Iec104NosType nameOfSection;
    Iec104LofType lengthOfFileOrSection;
    Iec104SrqType srq;
}__attribute__((packed));

struct Iec104F_SR_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_SR_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type F_SC_NA_1
// Ident 122
// Call directory, select file, call file, call section

struct Iec104F_SC_NA_1_IO_Subgroup
{
    Iec104NofType nameOfFile;
    Iec104NosType nameOfSection;
    Iec104ScqType scq;
}__attribute__((packed));

struct Iec104F_SC_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_SC_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type F_LS_NA_1
// Ident 123
// Last section, last segment

struct Iec104F_LS_NA_1_IO_Subgroup
{
    Iec104NofType nameOfFile;
    Iec104NosType nameOfSection;
    Iec104LsqType lsq;
    Iec104ChsType chs;
}__attribute__((packed));

struct Iec104F_LS_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_LS_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type F_AF_NA_1
// Ident 124
// ACK file, ACK section

struct Iec104F_AF_NA_1_IO_Subgroup
{
    Iec104NofType nameOfFile;
    Iec104NosType nameOfSection;
    Iec104AfqType afq;
}__attribute__((packed));

struct Iec104F_AF_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_AF_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type F_SG_NA_1
// Ident 125
// Single information object

struct Iec104F_SG_NA_1_IO_Subgroup
{
    Iec104NofType nameOfFile;
    Iec104NosType nameOfSection;
    Iec104LosType lengthOfSegment;
    Iec104SegmentType segment;
}__attribute__((packed));

struct Iec104F_SG_NA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_SG_NA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type F_DR_TA_1
// Ident 126
// Sequence of information elements in a single information object

struct Iec104F_DR_TA_1_IO_Subgroup
{
    Iec104NofType nameOfFileOrSubdirectory;
    Iec104LofType lengthOfFile;
    Iec104SofType sof;
    Iec104Cp56Time2aType creationTimeOfFile;
}__attribute__((packed));

struct Iec104F_DR_TA_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_DR_TA_1_IO_Subgroup subgroup;
}__attribute__((packed));


// ASDU Type F_SC_NB_1
// Ident 127
// QueryLog – Request archive file

struct Iec104F_SC_NB_1_IO_Subgroup
{
    Iec104NofType nameOfFile;
    Iec104Cp56Time2aType startTime;
    Iec104Cp56Time2aType stopTime;
}__attribute__((packed));

struct Iec104F_SC_NB_1_IO_Group
{
    Iec104InformationObjectAddressThreeOctetType ioa;
    Iec104F_SC_NB_1_IO_Subgroup subgroup;
}__attribute__((packed));


//
// Generic ASDU
//

struct Iec104GenericAsdu
{
    uint8_t typeId;
    Iec104VariableStructureQualifierType variableStructureQualifier;
    Iec104CauseOfTransmissionType causeOfTransmission;
    Iec104CommonAddressOfAsduType commonAddressOfAsdu;
    union
    {
        Iec104M_SP_NA_1_IO_Group m_sp_na_1;
        Iec104M_SP_TA_1_IO_Group m_sp_ta_1;
        Iec104M_DP_NA_1_IO_Group m_dp_na_1;
        Iec104M_DP_TA_1_IO_Group m_dp_ta_1;
        Iec104M_ST_NA_1_IO_Group m_st_na_1;
        Iec104M_ST_TA_1_IO_Group m_st_ta_1;
        Iec104M_BO_NA_1_IO_Group m_bo_na_1;
        Iec104M_BO_TA_1_IO_Group m_bo_ta_1;
        Iec104M_ME_NA_1_IO_Group m_me_na_1;
        Iec104M_ME_TA_1_IO_Group m_me_ta_1;
        Iec104M_ME_NB_1_IO_Group m_me_nb_1;
        Iec104M_ME_TB_1_IO_Group m_me_tb_1;
        Iec104M_ME_NC_1_IO_Group m_me_nc_1;
        Iec104M_ME_TC_1_IO_Group m_me_tc_1;
        Iec104M_IT_NA_1_IO_Group m_it_na_1;
        Iec104M_IT_TA_1_IO_Group m_it_ta_1;
        Iec104M_EP_TA_1_IO_Group m_ep_ta_1;
        Iec104M_EP_TB_1_IO_Group m_ep_tb_1;
        Iec104M_EP_TC_1_IO_Group m_ep_tc_1;
        Iec104M_PS_NA_1_IO_Group m_ps_na_1;
        Iec104M_ME_ND_1_IO_Group m_me_nd_1;
        Iec104M_SP_TB_1_IO_Group m_sp_tb_1;
        Iec104M_DP_TB_1_IO_Group m_dp_tb_1;
        Iec104M_ST_TB_1_IO_Group m_st_tb_1;
        Iec104M_BO_TB_1_IO_Group m_bo_tb_1;
        Iec104M_ME_TD_1_IO_Group m_me_td_1;
        Iec104M_ME_TE_1_IO_Group m_me_te_1;
        Iec104M_ME_TF_1_IO_Group m_me_tf_1;
        Iec104M_IT_TB_1_IO_Group m_it_tb_1;
        Iec104M_EP_TD_1_IO_Group m_ep_td_1;
        Iec104M_EP_TE_1_IO_Group m_ep_te_1;
        Iec104M_EP_TF_1_IO_Group m_ep_tf_1;
        Iec104C_SC_NA_1_IO_Group c_sc_na_1;
        Iec104C_DC_NA_1_IO_Group c_dc_na_1;
        Iec104C_RC_NA_1_IO_Group c_rc_na_1;
        Iec104C_SE_NA_1_IO_Group c_se_na_1;
        Iec104C_SE_NB_1_IO_Group c_se_nb_1;
        Iec104C_SE_NC_1_IO_Group c_se_nc_1;
        Iec104C_BO_NA_1_IO_Group c_bo_na_1;
        Iec104C_SC_TA_1_IO_Group c_sc_ta_1;
        Iec104C_DC_TA_1_IO_Group c_dc_ta_1;
        Iec104C_RC_TA_1_IO_Group c_rc_ta_1;
        Iec104C_SE_TA_1_IO_Group c_se_ta_1;
        Iec104C_SE_TB_1_IO_Group c_se_tb_1;
        Iec104C_SE_TC_1_IO_Group c_se_tc_1;
        Iec104C_BO_TA_1_IO_Group c_bo_ta_1;
        Iec104M_EI_NA_1_IO_Group m_ei_na_1;
        Iec104C_IC_NA_1_IO_Group c_ic_na_1;
        Iec104C_CI_NA_1_IO_Group c_ci_na_1;
        Iec104C_RD_NA_1_IO_Group c_rd_na_1;
        Iec104C_CS_NA_1_IO_Group c_cs_na_1;
        Iec104C_TS_NA_1_IO_Group c_ts_na_1;
        Iec104C_RP_NA_1_IO_Group c_rp_na_1;
        Iec104C_CD_NA_1_IO_Group c_cd_na_1;
        Iec104C_TS_TA_1_IO_Group c_ts_ta_1;
        Iec104P_ME_NA_1_IO_Group p_me_na_1;
        Iec104P_ME_NB_1_IO_Group p_me_nb_1;
        Iec104P_ME_NC_1_IO_Group p_me_nc_1;
        Iec104P_AC_NA_1_IO_Group p_ac_na_1;
        Iec104F_FR_NA_1_IO_Group f_fr_na_1;
        Iec104F_SR_NA_1_IO_Group f_sr_na_1;
        Iec104F_SC_NA_1_IO_Group f_sc_na_1;
        Iec104F_LS_NA_1_IO_Group f_ls_na_1;
        Iec104F_AF_NA_1_IO_Group f_af_na_1;
        Iec104F_SG_NA_1_IO_Group f_sg_na_1;
        Iec104F_DR_TA_1_IO_Group f_dr_ta_1;
        Iec104F_SC_NB_1_IO_Group f_sc_nb_1;
    };
}__attribute__((packed));


//
// APCI structs
//

// Header fields common to every APCI
struct Iec104Header
{
    uint8_t start;
    uint8_t length;
}__attribute__((packed));

// APCI Type U
struct Iec104ApciU
{
    Iec104Header header;
    uint8_t apciTypeMajor : 1;
    uint8_t apciTypeMinor : 1;
    uint8_t startdtAct : 1;
    uint8_t startdtCon : 1;
    uint8_t stopdtAct : 1;
    uint8_t stopdtCon : 1;
    uint8_t testfrAct : 1;
    uint8_t testfrCon : 1;
    uint8_t reserved1;
    uint16_t reserved2 : 1;
    uint16_t reserved3 : 15;
}__attribute__((packed));

// APCI Type S
struct Iec104ApciS
{
    Iec104Header header;
    uint16_t apciTypeMajor : 1;
    uint16_t apciTypeMinor : 1;
    uint16_t reserved1 : 14;
    uint16_t reserved2 : 1;
    uint16_t recvSeq : 15;
}__attribute__((packed));

// APCI Type I
struct Iec104ApciI
{
    Iec104Header header;
    uint16_t apciTypeMajor : 1;
    uint16_t sendSeq : 15;
    uint16_t reserved : 1;
    uint16_t recvSeq : 15;
    Iec104GenericAsdu asdu;
}__attribute__((packed));

// structs used to determine if there is an issue with the passed ASDU
struct Iec104AsduCheckCauseOfTx
{
    uint64_t percyc : 1;
    uint64_t back : 1;
    uint64_t spont : 1;
    uint64_t init : 1;
    uint64_t req : 1;
    uint64_t act : 1;
    uint64_t actcon : 1;
    uint64_t deact : 1;
    uint64_t deactcon : 1;
    uint64_t actterm : 1;
    uint64_t retrem : 1;
    uint64_t retloc : 1;
    uint64_t file : 1;
    uint64_t inrogen : 1;
    uint64_t inro1 : 1;
    uint64_t inro2 : 1;
    uint64_t inro3 : 1;
    uint64_t inro4 : 1;
    uint64_t inro5 : 1;
    uint64_t inro6 : 1;
    uint64_t inro7 : 1;
    uint64_t inro8 : 1;
    uint64_t inro9 : 1;
    uint64_t inro10 : 1;
    uint64_t inro11 : 1;
    uint64_t inro12 : 1;
    uint64_t inro13 : 1;
    uint64_t inro14 : 1;
    uint64_t inro15 : 1;
    uint64_t inro16 : 1;
    uint64_t reqcogen : 1;
    uint64_t reqco1 : 1;
    uint64_t reqco2 : 1;
    uint64_t reqco3 : 1;
    uint64_t reqco4 : 1;
    uint64_t unk_type_id : 1;
    uint64_t unk_cause_tx : 1;
    uint64_t unk_common_addr : 1;
    uint64_t unk_info_addr : 1;
};

struct Iec104AsduCheck
{
    const Iec104ApciI* apci;
    bool sq0Allowed;
    bool sq1Allowed;
    bool multipleIOAllowed;
    Iec104AsduCheckCauseOfTx checkCauseOfTx;
};

#endif

