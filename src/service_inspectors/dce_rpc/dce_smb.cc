//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb.cc author Rashmi Pitre <rrp@cisco.com>

#include "dce_smb.h"
#include "dce_smb_paf.h"
#include "dce_smb_module.h"
#include "dce_list.h"
#include "main/snort_debug.h"
#include "file_api/file_service.h"
#include "utils/util.h"
#include "detection/detect.h"

THREAD_LOCAL int dce2_smb_inspector_instances = 0;

THREAD_LOCAL dce2SmbStats dce2_smb_stats;
THREAD_LOCAL Packet* dce2_smb_rpkt[DCE2_SMB_RPKT_TYPE_MAX] = { nullptr, nullptr, nullptr,
                                                               nullptr };

THREAD_LOCAL ProfileStats dce2_smb_pstat_main;
THREAD_LOCAL ProfileStats dce2_smb_pstat_session;
THREAD_LOCAL ProfileStats dce2_smb_pstat_new_session;
THREAD_LOCAL ProfileStats dce2_smb_pstat_detect;
THREAD_LOCAL ProfileStats dce2_smb_pstat_log;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_seg;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_frag;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_reass;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_ctx;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_seg;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_req;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_uid;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_tid;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_fid;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file_detect;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file_api;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_fingerprint;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_negotiate;

/********************************************************************
 * Enums
 ********************************************************************/
enum DCE2_SmbComError
{
    // No errors associated with the command
    DCE2_SMB_COM_ERROR__COMMAND_OK          = 0x0000,

    // An error was reported in the SMB response header
    DCE2_SMB_COM_ERROR__STATUS_ERROR        = 0x0001,

    // An invalid word count makes it unlikely any data accessed will be correct
    // and if accessed the possibility of accessing out of bounds data
    DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT  = 0x0002,

    // An invalid byte count just means the byte count is not right for
    // the command processed.  The command can still be processed but
    // the byte count should not be used.  In general, the byte count
    // should not be used since Windows and Samba often times ignore it
    DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT  = 0x0004,

    // Not enough data to process command so don't try to access any
    // of the command's header or data.
    DCE2_SMB_COM_ERROR__BAD_LENGTH          = 0x0008
};

/********************************************************************
 * Structures
 ********************************************************************/
struct DCE2_SmbComInfo
{
    int smb_type;   // SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
    int cmd_error;  // mask of DCE2_SmbComError
    uint8_t smb_com;
    uint8_t word_count;
    uint16_t byte_count;
    uint16_t cmd_size;
};

// Inline accessor functions for DCE2_SmbComInfo

static inline bool DCE2_ComInfoIsResponse(const DCE2_SmbComInfo* com_info)
{
    return (com_info->smb_type == SMB_TYPE__RESPONSE) ? true : false;
}

static inline bool DCE2_ComInfoIsRequest(const DCE2_SmbComInfo* com_info)
{
    return (com_info->smb_type == SMB_TYPE__REQUEST) ? true : false;
}

static inline uint16_t DCE2_ComInfoByteCount(const DCE2_SmbComInfo* com_info)
{
    return com_info->byte_count;
}

static inline uint8_t DCE2_ComInfoSmbCom(const DCE2_SmbComInfo* com_info)
{
    return com_info->smb_com;
}

static inline uint16_t DCE2_ComInfoCommandSize(const DCE2_SmbComInfo* com_info)
{
    return com_info->cmd_size;
}

static inline bool DCE2_ComInfoIsStatusError(const DCE2_SmbComInfo* com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__STATUS_ERROR) ? true : false;
}

static inline bool DCE2_ComInfoIsInvalidWordCount(const DCE2_SmbComInfo* com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT) ? true : false;
}

static inline bool DCE2_ComInfoIsBadLength(const DCE2_SmbComInfo* com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__BAD_LENGTH) ? true : false;
}

static inline uint8_t DCE2_ComInfoWordCount(const DCE2_SmbComInfo* com_info)
{
    return com_info->word_count;
}

// If this returns false, the command should not be processed
static inline bool DCE2_ComInfoCanProcessCommand(const DCE2_SmbComInfo* com_info)
{
    if (DCE2_ComInfoIsBadLength(com_info)
        || DCE2_ComInfoIsStatusError(com_info)
        || DCE2_ComInfoIsInvalidWordCount(com_info))
        return false;
    return true;
}

/********************************************************************
 * Global variables
 ********************************************************************/
typedef DCE2_Ret (* DCE2_SmbComFunc)(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);

DCE2_SmbComFunc smb_com_funcs[SMB_MAX_NUM_COMS];
uint8_t smb_wcts[SMB_MAX_NUM_COMS][2][32];
uint16_t smb_bccs[SMB_MAX_NUM_COMS][2][2];
DCE2_SmbComFunc smb_chain_funcs[DCE2_POLICY__MAX][SMB_ANDX_COM__MAX][SMB_MAX_NUM_COMS];
bool smb_deprecated_coms[SMB_MAX_NUM_COMS];
bool smb_unusual_coms[SMB_MAX_NUM_COMS];
SmbAndXCom smb_chain_map[SMB_MAX_NUM_COMS];

const char* smb_com_strings[SMB_MAX_NUM_COMS] =
{
    "Create Directory",            // 0x00
    "Delete Directory",            // 0x01
    "Open",                        // 0x02
    "Create",                      // 0x03
    "Close",                       // 0x04
    "Flush",                       // 0x05
    "Delete",                      // 0x06
    "Rename",                      // 0x07
    "Query Information",           // 0x08
    "Set Information",             // 0x09
    "Read",                        // 0x0A
    "Write",                       // 0x0B
    "Lock Byte Range",             // 0x0C
    "Unlock Byte Range",           // 0x0D
    "Create Temporary",            // 0x0E
    "Create New",                  // 0x0F
    "Check Directory",             // 0x10
    "Process Exit",                // 0x11
    "Seek",                        // 0x12
    "Lock And Read",               // 0x13
    "Write And Unlock",            // 0x14
    "Unknown",                     // 0X15
    "Unknown",                     // 0X16
    "Unknown",                     // 0X17
    "Unknown",                     // 0X18
    "Unknown",                     // 0X19
    "Read Raw",                    // 0x1A
    "Read Mpx",                    // 0x1B
    "Read Mpx Secondary",          // 0x1C
    "Write Raw",                   // 0x1D
    "Write Mpx",                   // 0x1E
    "Write Mpx Secondary",         // 0x1F
    "Write Complete",              // 0x20
    "Query Server",                // 0x21
    "Set Information2",            // 0x22
    "Query Information2",          // 0x23
    "Locking AndX",                // 0x24
    "Transaction",                 // 0x25
    "Transaction Secondary",       // 0x26
    "Ioctl",                       // 0x27
    "Ioctl Secondary",             // 0x28
    "Copy",                        // 0x29
    "Move",                        // 0x2A
    "Echo",                        // 0x2B
    "Write And Close",             // 0x2C
    "Open AndX",                   // 0x2D
    "Read AndX",                   // 0x2E
    "Write AndX",                  // 0x2F
    "New File Size",               // 0x30
    "Close And Tree Disc",         // 0x31
    "Transaction2",                // 0x32
    "Transaction2 Secondary",      // 0x33
    "Find Close2",                 // 0x34
    "Find Notify Close",           // 0x35
    "Unknown",                     // 0X36
    "Unknown",                     // 0X37
    "Unknown",                     // 0X38
    "Unknown",                     // 0X39
    "Unknown",                     // 0X3A
    "Unknown",                     // 0X3B
    "Unknown",                     // 0X3C
    "Unknown",                     // 0X3D
    "Unknown",                     // 0X3E
    "Unknown",                     // 0X3F
    "Unknown",                     // 0X40
    "Unknown",                     // 0X41
    "Unknown",                     // 0X42
    "Unknown",                     // 0X43
    "Unknown",                     // 0X44
    "Unknown",                     // 0X45
    "Unknown",                     // 0X46
    "Unknown",                     // 0X47
    "Unknown",                     // 0X48
    "Unknown",                     // 0X49
    "Unknown",                     // 0X4A
    "Unknown",                     // 0X4B
    "Unknown",                     // 0X4C
    "Unknown",                     // 0X4D
    "Unknown",                     // 0X4E
    "Unknown",                     // 0X4F
    "Unknown",                     // 0X50
    "Unknown",                     // 0X51
    "Unknown",                     // 0X52
    "Unknown",                     // 0X53
    "Unknown",                     // 0X54
    "Unknown",                     // 0X55
    "Unknown",                     // 0X56
    "Unknown",                     // 0X57
    "Unknown",                     // 0X58
    "Unknown",                     // 0X59
    "Unknown",                     // 0X5A
    "Unknown",                     // 0X5B
    "Unknown",                     // 0X5C
    "Unknown",                     // 0X5D
    "Unknown",                     // 0X5E
    "Unknown",                     // 0X5F
    "Unknown",                     // 0X60
    "Unknown",                     // 0X61
    "Unknown",                     // 0X62
    "Unknown",                     // 0X63
    "Unknown",                     // 0X64
    "Unknown",                     // 0X65
    "Unknown",                     // 0X66
    "Unknown",                     // 0X67
    "Unknown",                     // 0X68
    "Unknown",                     // 0X69
    "Unknown",                     // 0X6A
    "Unknown",                     // 0X6B
    "Unknown",                     // 0X6C
    "Unknown",                     // 0X6D
    "Unknown",                     // 0X6E
    "Unknown",                     // 0X6F
    "Tree Connect",                // 0x70
    "Tree Disconnect",             // 0x71
    "Negotiate",                   // 0x72
    "Session Setup AndX",          // 0x73
    "Logoff AndX",                 // 0x74
    "Tree Connect AndX",           // 0x75
    "Unknown",                     // 0X76
    "Unknown",                     // 0X77
    "Unknown",                     // 0X78
    "Unknown",                     // 0X79
    "Unknown",                     // 0X7A
    "Unknown",                     // 0X7B
    "Unknown",                     // 0X7C
    "Unknown",                     // 0X7D
    "Security Package AndX",       // 0x7E
    "Unknown",                     // 0X7F
    "Query Information Disk",      // 0x80
    "Search",                      // 0x81
    "Find",                        // 0x82
    "Find Unique",                 // 0x83
    "Find Close",                  // 0x84
    "Unknown",                     // 0X85
    "Unknown",                     // 0X86
    "Unknown",                     // 0X87
    "Unknown",                     // 0X88
    "Unknown",                     // 0X89
    "Unknown",                     // 0X8A
    "Unknown",                     // 0X8B
    "Unknown",                     // 0X8C
    "Unknown",                     // 0X8D
    "Unknown",                     // 0X8E
    "Unknown",                     // 0X8F
    "Unknown",                     // 0X90
    "Unknown",                     // 0X91
    "Unknown",                     // 0X92
    "Unknown",                     // 0X93
    "Unknown",                     // 0X94
    "Unknown",                     // 0X95
    "Unknown",                     // 0X96
    "Unknown",                     // 0X97
    "Unknown",                     // 0X98
    "Unknown",                     // 0X99
    "Unknown",                     // 0X9A
    "Unknown",                     // 0X9B
    "Unknown",                     // 0X9C
    "Unknown",                     // 0X9D
    "Unknown",                     // 0X9E
    "Unknown",                     // 0X9F
    "Nt Transact",                 // 0xA0
    "Nt Transact Secondary",       // 0xA1
    "Nt Create AndX",              // 0xA2
    "Unknown",                     // 0XA3
    "Nt Cancel",                   // 0xA4
    "Nt Rename",                   // 0xA5
    "Unknown",                     // 0XA6
    "Unknown",                     // 0XA7
    "Unknown",                     // 0XA8
    "Unknown",                     // 0XA9
    "Unknown",                     // 0XAA
    "Unknown",                     // 0XAB
    "Unknown",                     // 0XAC
    "Unknown",                     // 0XAD
    "Unknown",                     // 0XAE
    "Unknown",                     // 0XAF
    "Unknown",                     // 0XB0
    "Unknown",                     // 0XB1
    "Unknown",                     // 0XB2
    "Unknown",                     // 0XB3
    "Unknown",                     // 0XB4
    "Unknown",                     // 0XB5
    "Unknown",                     // 0XB6
    "Unknown",                     // 0XB7
    "Unknown",                     // 0XB8
    "Unknown",                     // 0XB9
    "Unknown",                     // 0XBA
    "Unknown",                     // 0XBB
    "Unknown",                     // 0XBC
    "Unknown",                     // 0XBD
    "Unknown",                     // 0XBE
    "Unknown",                     // 0XBF
    "Open Print File",             // 0xC0
    "Write Print File",            // 0xC1
    "Close Print File",            // 0xC2
    "Get Print Queue",             // 0xC3
    "Unknown",                     // 0XC4
    "Unknown",                     // 0XC5
    "Unknown",                     // 0XC6
    "Unknown",                     // 0XC7
    "Unknown",                     // 0XC8
    "Unknown",                     // 0XC9
    "Unknown",                     // 0XCA
    "Unknown",                     // 0XCB
    "Unknown",                     // 0XCC
    "Unknown",                     // 0XCD
    "Unknown",                     // 0XCE
    "Unknown",                     // 0XCF
    "Unknown",                     // 0XD0
    "Unknown",                     // 0XD1
    "Unknown",                     // 0XD2
    "Unknown",                     // 0XD3
    "Unknown",                     // 0XD4
    "Unknown",                     // 0XD5
    "Unknown",                     // 0XD6
    "Unknown",                     // 0XD7
    "Read Bulk",                   // 0xD8
    "Write Bulk",                  // 0xD9
    "Write Bulk Data",             // 0xDA
    "Unknown",                     // 0XDB
    "Unknown",                     // 0XDC
    "Unknown",                     // 0XDD
    "Unknown",                     // 0XDE
    "Unknown",                     // 0XDF
    "Unknown",                     // 0XE0
    "Unknown",                     // 0XE1
    "Unknown",                     // 0XE2
    "Unknown",                     // 0XE3
    "Unknown",                     // 0XE4
    "Unknown",                     // 0XE5
    "Unknown",                     // 0XE6
    "Unknown",                     // 0XE7
    "Unknown",                     // 0XE8
    "Unknown",                     // 0XE9
    "Unknown",                     // 0XEA
    "Unknown",                     // 0XEB
    "Unknown",                     // 0XEC
    "Unknown",                     // 0XED
    "Unknown",                     // 0XEE
    "Unknown",                     // 0XEF
    "Unknown",                     // 0XF0
    "Unknown",                     // 0XF1
    "Unknown",                     // 0XF2
    "Unknown",                     // 0XF3
    "Unknown",                     // 0XF4
    "Unknown",                     // 0XF5
    "Unknown",                     // 0XF6
    "Unknown",                     // 0XF7
    "Unknown",                     // 0XF8
    "Unknown",                     // 0XF9
    "Unknown",                     // 0XFA
    "Unknown",                     // 0XFB
    "Unknown",                     // 0XFC
    "Unknown",                     // 0XFD
    "Invalid",                     // 0xFE
    "No AndX Command"              // 0xFF
};

const char* smb_transaction_sub_command_strings[TRANS_SUBCOM_MAX] =
{
    "Unknown",                               // 0x0000
    "TRANS_SET_NMPIPE_STATE",                // 0x0001
    "Unknown",                               // 0x0002
    "Unknown",                               // 0x0003
    "Unknown",                               // 0x0004
    "Unknown",                               // 0x0005
    "Unknown",                               // 0x0006
    "Unknown",                               // 0x0007
    "Unknown",                               // 0x0008
    "Unknown",                               // 0x0009
    "Unknown",                               // 0x000A
    "Unknown",                               // 0x000B
    "Unknown",                               // 0x000C
    "Unknown",                               // 0x000D
    "Unknown",                               // 0x000E
    "Unknown",                               // 0x000F
    "Unknown",                               // 0x0010
    "TRANS_RAW_READ_NMPIPE",                 // 0x0011
    "Unknown",                               // 0x0012
    "Unknown",                               // 0x0013
    "Unknown",                               // 0x0014
    "Unknown",                               // 0x0015
    "Unknown",                               // 0x0016
    "Unknown",                               // 0x0017
    "Unknown",                               // 0x0018
    "Unknown",                               // 0x0019
    "Unknown",                               // 0x001A
    "Unknown",                               // 0x001B
    "Unknown",                               // 0x001C
    "Unknown",                               // 0x001D
    "Unknown",                               // 0x001E
    "Unknown",                               // 0x001F
    "Unknown",                               // 0x0020
    "TRANS_QUERY_NMPIPE_STATE",              // 0x0021
    "TRANS_QUERY_NMPIPE_INFO",               // 0x0022
    "TRANS_PEEK_NMPIPE",                     // 0x0023
    "Unknown",                               // 0x0024
    "Unknown",                               // 0x0025
    "TRANS_TRANSACT_NMPIPE",                 // 0x0026
    "Unknown",                               // 0x0027
    "Unknown",                               // 0x0028
    "Unknown",                               // 0x0029
    "Unknown",                               // 0x002A
    "Unknown",                               // 0x002B
    "Unknown",                               // 0x002C
    "Unknown",                               // 0x002D
    "Unknown",                               // 0x002E
    "Unknown",                               // 0x002F
    "Unknown",                               // 0x0030
    "TRANS_RAW_WRITE_NMPIPE",                // 0x0031
    "Unknown",                               // 0x0032
    "Unknown",                               // 0x0033
    "Unknown",                               // 0x0034
    "Unknown",                               // 0x0035
    "TRANS_READ_NMPIPE",                     // 0x0036
    "TRANS_WRITE_NMPIPE",                    // 0x0037
    "Unknown",                               // 0x0038
    "Unknown",                               // 0x0039
    "Unknown",                               // 0x003A
    "Unknown",                               // 0x003B
    "Unknown",                               // 0x003C
    "Unknown",                               // 0x003D
    "Unknown",                               // 0x003E
    "Unknown",                               // 0x003F
    "Unknown",                               // 0x0040
    "Unknown",                               // 0x0041
    "Unknown",                               // 0x0042
    "Unknown",                               // 0x0043
    "Unknown",                               // 0x0044
    "Unknown",                               // 0x0045
    "Unknown",                               // 0x0046
    "Unknown",                               // 0x0047
    "Unknown",                               // 0x0048
    "Unknown",                               // 0x0049
    "Unknown",                               // 0x004A
    "Unknown",                               // 0x004B
    "Unknown",                               // 0x004C
    "Unknown",                               // 0x004D
    "Unknown",                               // 0x004E
    "Unknown",                               // 0x004F
    "Unknown",                               // 0x0050
    "Unknown",                               // 0x0051
    "Unknown",                               // 0x0052
    "TRANS_WAIT_NMPIPE",                     // 0x0053
    "TRANS_CALL_NMPIPE"                      // 0x0054
};

/********************************************************************
 * Private function prototypes
 ********************************************************************/
static inline int DCE2_SmbType(DCE2_SmbSsnData*);
static inline bool DCE2_SmbIsRawData(DCE2_SmbSsnData*);
static inline uint32_t* DCE2_SmbGetIgnorePtr(DCE2_SmbSsnData*);
static inline DCE2_SmbDataState* DCE2_SmbGetDataState(DCE2_SmbSsnData*);
static inline void DCE2_SmbSetValidWordCount(uint8_t, uint8_t, uint8_t);
static inline bool DCE2_SmbIsValidWordCount(uint8_t, uint8_t, uint8_t);
static inline void DCE2_SmbSetValidByteCount(uint8_t, uint8_t, uint16_t, uint16_t);
static inline bool DCE2_SmbIsValidByteCount(uint8_t, uint8_t, uint16_t);
static DCE2_Ret DCE2_SmbHdrChecks(DCE2_SmbSsnData*, const SmbNtHdr*);
static uint32_t DCE2_IgnoreJunkData(const uint8_t*, uint16_t, uint32_t);
static bool DCE2_SmbIsTidIPC(DCE2_SmbSsnData*, const uint16_t);
static void DCE2_SmbCheckCommand(DCE2_SmbSsnData*,
    const SmbNtHdr*, const uint8_t, const uint8_t*, uint32_t, DCE2_SmbComInfo&);
static void DCE2_SmbProcessCommand(DCE2_SmbSsnData*, const SmbNtHdr*, const uint8_t*, uint32_t);
static DCE2_SmbRequestTracker* DCE2_SmbInspect(DCE2_SmbSsnData*, const SmbNtHdr*);
static bool DCE2_SmbAutodetect(Packet* p);
static DCE2_SmbRequestTracker* DCE2_SmbNewRequestTracker(DCE2_SmbSsnData*, const SmbNtHdr*);
static DCE2_SmbRequestTracker* DCE2_SmbFindRequestTracker(DCE2_SmbSsnData*,
    const SmbNtHdr*);
static void DCE2_SmbCleanTransactionTracker(DCE2_SmbTransactionTracker*);
static void DCE2_SmbCleanRequestTracker(DCE2_SmbRequestTracker*);
static void DCE2_SmbRemoveRequestTracker(DCE2_SmbSsnData*, DCE2_SmbRequestTracker*);
static DCE2_SmbFileTracker* DCE2_SmbNewFileTracker(DCE2_SmbSsnData*,
    const uint16_t, const uint16_t, const uint16_t);
static DCE2_SmbFileTracker* DCE2_SmbGetFileTracker(DCE2_SmbSsnData*,
    const uint16_t);
static DCE2_SmbFileTracker* DCE2_SmbGetTmpFileTracker(DCE2_SmbRequestTracker*);
static void DCE2_SmbRemoveFileTracker(DCE2_SmbSsnData*, DCE2_SmbFileTracker*);
static void DCE2_SmbCleanFileTracker(DCE2_SmbFileTracker*);
static int DCE2_SmbUidTidFidCompare(const void*, const void*);
static DCE2_Ret DCE2_SmbFindUid(DCE2_SmbSsnData*, const uint16_t);
static void DCE2_SmbInsertUid(DCE2_SmbSsnData*, const uint16_t);
static void DCE2_SmbRemoveUid(DCE2_SmbSsnData*, const uint16_t);
static void DCE2_SmbFileTrackerDataFree(void*);
static void DCE2_SmbCleanSessionFileTracker(DCE2_SmbSsnData*, DCE2_SmbFileTracker*);
static void DCE2_SmbRemoveFileTrackerFromRequestTrackers(DCE2_SmbSsnData*,
    DCE2_SmbFileTracker*);
static DCE2_SmbFileTracker* DCE2_SmbDequeueTmpFileTracker(DCE2_SmbSsnData*,
    DCE2_SmbRequestTracker*, const uint16_t);
static char* DCE2_SmbGetString(const uint8_t*, uint32_t, bool, bool);
static inline DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData*, const uint16_t,
    const uint8_t*, uint32_t, uint64_t);
static DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData*,
    const uint8_t*, uint32_t);
static inline void DCE2_SmbCheckFmtData(DCE2_SmbSsnData*, const uint32_t,
    const uint16_t, const uint8_t, const uint16_t, const uint16_t);
static inline DCE2_Ret DCE2_SmbCheckData(DCE2_SmbSsnData*, const uint8_t*,
    const uint8_t*, const uint32_t, const uint16_t, const uint32_t, uint16_t);
static inline bool DCE2_SmbIsTransactionComplete(DCE2_SmbTransactionTracker*);
static inline DCE2_Ret DCE2_SmbCheckAndXOffset(const uint8_t*,
    const uint8_t*, const uint32_t);
static void DCE2_SmbQueueTmpFileTracker(DCE2_SmbSsnData*,
    DCE2_SmbRequestTracker*, const uint16_t, const uint16_t);
static DCE2_Ret DCE2_SmbFindTid(DCE2_SmbSsnData*, const uint16_t);
static void DCE2_SmbRemoveTid(DCE2_SmbSsnData*, const uint16_t);
static void DCE2_SmbInsertTid(DCE2_SmbSsnData*, const uint16_t, const bool);
static void DCE2_SmbInvalidShareCheck(DCE2_SmbSsnData*,
    const SmbNtHdr*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbUpdateTransRequest(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbUpdateTransResponse(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbValidateTransactionFields(const uint8_t*,
    const uint8_t*, const uint32_t, const uint16_t, const uint32_t,
    const uint32_t, const uint32_t, const uint32_t, const uint32_t,
    const uint32_t, const uint32_t, const uint32_t);
static DCE2_Ret DCE2_SmbCheckTransDataParams(
    const uint8_t*, const uint8_t*, const uint32_t, const uint16_t,
    const uint32_t, const uint32_t, const uint32_t, const uint32_t);
static DCE2_Ret DCE2_SmbCheckTotalCount(
    const uint32_t, const uint32_t, const uint32_t);
static DCE2_Ret DCE2_SmbValidateTransactionSent(
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
static DCE2_Ret DCE2_SmbOpen(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbCreate(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbClose(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbRename(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbRead(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbWrite(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbCreateNew(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbLockAndRead(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbWriteAndUnlock(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbOpenAndX(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbReadAndX(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbWriteAndX(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbSessionSetupAndX(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbNegotiate(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbTreeConnectAndX(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbTreeConnect(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbNtCreateAndX(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbTreeDisconnect(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbLogoffAndX(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbTransactionReq(DCE2_SmbSsnData*,
    DCE2_SmbTransactionTracker*, const uint8_t*, uint32_t,
    const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbTransaction(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);

/********************************************************************
 * Function: DCE2_SmbType()
 *
 * Purpose:
 *  Since Windows and Samba don't seem to care or even look at the
 *  actual flag in the SMB header, make the determination based on
 *  whether from client or server.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - session data structure that has the raw
 *     packet and packet flags to make determination
 *
 * Returns:
 *  SMB_TYPE__REQUEST if packet is from client
 *  SMB_TYPE__RESPONSE if packet is from server
 *
 ********************************************************************/
static inline int DCE2_SmbType(DCE2_SmbSsnData* ssd)
{
    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
        return SMB_TYPE__REQUEST;
    else
        return SMB_TYPE__RESPONSE;
}

/********************************************************************
 * Function: DCE2_SmbIsRawData()
 *
 * Purpose:
 *  To determine if the current state is such that a raw read or
 *  write is expected.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  bool -  True if expecting raw data.
 *          False if not.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsRawData(DCE2_SmbSsnData* ssd)
{
    return (ssd->pdu_state == DCE2_SMB_PDU_STATE__RAW_DATA);
}

/********************************************************************
 * Function: DCE2_SmbGetIgnorePtr()
 *
 * Returns a pointer to the bytes we are ignoring on client or
 * server side.  Bytes are ignored if they are associated with
 * data we are not interested in.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  uint32_t *
 *      Pointer to the client or server ignore bytes.
 *
 ********************************************************************/
static inline uint32_t* DCE2_SmbGetIgnorePtr(DCE2_SmbSsnData* ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_ignore_bytes;
    return &ssd->cli_ignore_bytes;
}

/********************************************************************
 * Function: DCE2_SmbGetDataState()
 *
 * Returns a pointer to the data state of client or server
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  DCE2_SmbDataState *
 *      Pointer to the client or server data state.
 *
 ********************************************************************/
static inline DCE2_SmbDataState* DCE2_SmbGetDataState(DCE2_SmbSsnData* ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_data_state;
    return &ssd->cli_data_state;
}

/********************************************************************
 * Function: DCE2_SmbSetValidWordCount()
 *
 * Purpose:
 *  Initializes global data for valid word counts for supported
 *  SMB command requests and responses.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the valid word count
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbSetValidWordCount(uint8_t com,
    uint8_t resp, uint8_t wct)
{
    smb_wcts[com][resp][wct/8] |= (1 << (wct % 8));
}

/********************************************************************
 * Function: DCE2_SmbIsValidWordCount()
 *
 * Purpose:
 *  Checks if a word count is valid for a given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the word count to validate
 *
 * Returns:
 *  bool - true if valid, false if not valid.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsValidWordCount(uint8_t com,
    uint8_t resp, uint8_t wct)
{
    return (smb_wcts[com][resp][wct/8] & (1 << (wct % 8))) ? true : false;
}

/********************************************************************
 * Function: DCE2_SmbSetValidByteCount()
 *
 * Purpose:
 *  Initializes global data for valid byte counts as a range for
 *  supported SMB command requests and responses.
 *  Since a byte count is 2 bytes, a 4 byte type is used to store
 *  the range.  The maximum is in the most significant 2 bytes and
 *  the minimum in the least significant 2 bytes.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the minimum word count that is valid
 *  uint8_t - the maximum word count that is valid
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbSetValidByteCount(uint8_t com,
    uint8_t resp, uint16_t min, uint16_t max)
{
    smb_bccs[com][resp][0] = min;
    smb_bccs[com][resp][1] = max;
}

/********************************************************************
 * Function: DCE2_SmbIsValidByteCount()
 *
 * Purpose:
 *  Checks if a byte count is valid for a given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the byte count to validate
 *
 * Returns:
 *  bool - true if valid, false if not valid.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsValidByteCount(uint8_t com,
    uint8_t resp, uint16_t bcc)
{
    return ((bcc < smb_bccs[com][resp][0])
           || (bcc > smb_bccs[com][resp][1])) ? false : true;
}

static inline uint8_t SmbCom(const SmbNtHdr* hdr)
{
    return hdr->smb_com;
}

static bool SmbStatusNtCodes(const SmbNtHdr* hdr)
{
    if (alignedNtohs(&hdr->smb_flg2) & SMB_FLG2__NT_CODES)
        return true;
    return false;
}

static inline uint32_t SmbNtStatus(const SmbNtHdr* hdr)
{
    return alignedNtohl(&hdr->smb_status.nt_status);
}

static inline uint8_t SmbStatusClass(const SmbNtHdr* hdr)
{
    return hdr->smb_status.smb_status.smb_class;
}

static inline uint16_t SmbStatusCode(const SmbNtHdr* hdr)
{
    return alignedNtohs(&hdr->smb_status.smb_status.smb_code);
}

static inline uint8_t SmbNtStatusSeverity(const SmbNtHdr* hdr)
{
    return (uint8_t)(SmbNtStatus(hdr) >> 30);
}

static inline uint16_t SmbPid(const SmbNtHdr* hdr)
{
    return alignedNtohs(&hdr->smb_pid);
}

static inline uint16_t SmbMid(const SmbNtHdr* hdr)
{
    return alignedNtohs(&hdr->smb_mid);
}

// This function is obviously deficient.  Need to do a lot more
// testing, research and reading MS-CIFS, MS-SMB and MS-ERREF.
static bool SmbError(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        /* Nt status codes are being used.  First 2 bits indicate
         * severity. */
        switch (SmbNtStatusSeverity(hdr))
        {
        case SMB_NT_STATUS_SEVERITY__SUCCESS:
        case SMB_NT_STATUS_SEVERITY__INFORMATIONAL:
        case SMB_NT_STATUS_SEVERITY__WARNING:
            return false;
        case SMB_NT_STATUS_SEVERITY__ERROR:
        default:
            break;
        }
    }
    else
    {
        switch (SmbStatusClass(hdr))
        {
        case SMB_ERROR_CLASS__SUCCESS:
            return false;
        case SMB_ERROR_CLASS__ERRDOS:
            if (SmbStatusCode(hdr) == SMB_ERRDOS__MORE_DATA)
                return false;
            break;
        case SMB_ERROR_CLASS__ERRSRV:
        case SMB_ERROR_CLASS__ERRHRD:
        case SMB_ERROR_CLASS__ERRCMD:
        default:
            break;
        }
    }

    return true;
}

static bool SmbBrokenPipe(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        uint32_t nt_status = SmbNtStatus(hdr);
        if ((nt_status == SMB_NT_STATUS__PIPE_BROKEN)
            || (nt_status == SMB_NT_STATUS__PIPE_DISCONNECTED))
            return true;
    }
    else
    {
        if (SmbStatusClass(hdr) == SMB_ERROR_CLASS__ERRDOS)
        {
            uint16_t smb_status = SmbStatusCode(hdr);
            if ((smb_status == SMB_ERRDOS__BAD_PIPE)
                || (smb_status == SMB_ERRDOS__PIPE_NOT_CONNECTED))
                return true;
        }
    }

    return false;
}

static inline uint16_t SmbUid(const SmbNtHdr* hdr)
{
    return alignedNtohs(&hdr->smb_uid);
}

static inline uint16_t SmbTid(const SmbNtHdr* hdr)
{
    return alignedNtohs(&hdr->smb_tid);
}

static inline bool SmbUnicode(const SmbNtHdr* hdr)
{
    return (alignedNtohs(&hdr->smb_flg2) & SMB_FLG2__UNICODE) ? true : false;
}

static inline bool SmbExtAttrReadOnly(const uint32_t ext_file_attrs)
{
    if (ext_file_attrs & SMB_EXT_FILE_ATTR_READONLY)
        return true;
    return false;
}

static inline bool SmbExtAttrHidden(const uint32_t ext_file_attrs)
{
    if (ext_file_attrs & SMB_EXT_FILE_ATTR_HIDDEN)
        return true;
    return false;
}

static inline bool SmbExtAttrSystem(const uint32_t ext_file_attrs)
{
    if (ext_file_attrs & SMB_EXT_FILE_ATTR_SYSTEM)
        return true;
    return false;
}

static inline bool SmbEvasiveFileAttrs(const uint32_t ext_file_attrs)
{
    return (SmbExtAttrReadOnly(ext_file_attrs)
           && SmbExtAttrHidden(ext_file_attrs)
           && SmbExtAttrSystem(ext_file_attrs));
}

static inline bool SmbErrorInvalidDeviceRequest(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        if (SmbNtStatus(hdr) == SMB_NT_STATUS__INVALID_DEVICE_REQUEST)
            return true;
    }
    else
    {
        if ((SmbStatusClass(hdr) == SMB_ERROR_CLASS__ERRSRV)
            && (SmbStatusCode(hdr) == SMB_ERRSRV__INVALID_DEVICE))
            return true;
    }

    return false;
}

static inline bool SmbErrorRangeNotLocked(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        if (SmbNtStatus(hdr) == SMB_NT_STATUS__RANGE_NOT_LOCKED)
            return true;
    }
    else
    {
        if ((SmbStatusClass(hdr) == SMB_ERROR_CLASS__ERRDOS)
            && (SmbStatusCode(hdr) == SMB_ERRDOS__NOT_LOCKED))
            return true;
    }

    return false;
}

/********************************************************************
 * Function: DCE2_SmbCheckFmtData()
 *
 * Purpose:
 *  Checks the data count in commands with formats, e.g.
 *  SMB_COM_WRITE, SMB_COM_WRITE_AND_CLOSE, SMB_COM_WRITE_AND_UNLOCK.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint32_t    - remaining NetBIOS PDU length
 *  const uint16_t    - advertised byte count
 *  const uint8_t     - data format specifier
 *  const uint16_t    - data count reported in command
 *  const uint16_t    - data count reported in format field
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbCheckFmtData(DCE2_SmbSsnData*,
    const uint32_t nb_len, const uint16_t bcc, const uint8_t fmt,
    const uint16_t com_dcnt, const uint16_t fmt_dcnt)
{
    if (fmt != SMB_FMT__DATA_BLOCK)
        dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
    if (com_dcnt != fmt_dcnt)
        dce_alert(GID_DCE2, DCE2_SMB_DCNT_MISMATCH, (dce2CommonStats*)&dce2_smb_stats);
    if (com_dcnt != (bcc - 3))
        dce_alert(GID_DCE2, DCE2_SMB_INVALID_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
    if (nb_len < com_dcnt)
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
}

/********************************************************************
 * Function: DCE2_IgnoreJunkData()
 *
 * Purpose:
 *   An evasion technique can be to put a bunch of junk data before
 *   the actual SMB request and it seems the MS implementation has
 *   no problem with it and seems to just ignore the data.  This
 *   function attempts to move past all the junk to get to the
 *   actual NetBIOS message request.
 *
 * Arguments:
 *   const uint8_t *  - pointer to the current position in the data
 *      being inspected
 *   uint16_t  -  the amount of data left to look at
 *   uint32_t  -  the amount of data to ignore if there doesn't seem
 *      to be any junk data.  Just use the length as if the bad
 *      NetBIOS header was good.
 *
 * Returns:
 *    uint32_t - the amount of bytes to ignore as junk.
 *
 ********************************************************************/
static uint32_t DCE2_IgnoreJunkData(const uint8_t* data_ptr, uint16_t data_len,
    uint32_t assumed_nb_len)
{
    const uint8_t* tmp_ptr = data_ptr;
    uint32_t ignore_bytes = 0;

    /* Try to find \xffSMB and go back 8 bytes to beginning
     * of what should be a Netbios header with type Session
     * Message (\x00) - do appropriate buffer checks to make
     * sure the index is in bounds. Ignore all intervening
     * bytes */

    while ((tmp_ptr + sizeof(uint32_t)) <= (data_ptr + data_len))
    {
        if ((SmbId((SmbNtHdr*)tmp_ptr) == DCE2_SMB_ID)
            || (SmbId((SmbNtHdr*)tmp_ptr) == DCE2_SMB2_ID))
        {
            break;
        }

        tmp_ptr++;
    }

    if ((tmp_ptr + sizeof(uint32_t)) > (data_ptr + data_len))
    {
        ignore_bytes = data_len;
    }
    else
    {
        if ((tmp_ptr - sizeof(NbssHdr)) > data_ptr)
            ignore_bytes = (tmp_ptr - data_ptr) - sizeof(NbssHdr);
        else  /* Just ignore whatever the bad NB header had as a length */
            ignore_bytes = assumed_nb_len;
    }

    return ignore_bytes;
}

/********************************************************************
 * Function:  DCE2_SmbIsTidIPC()
 *
 * Purpose: Checks to see if the TID passed in was to IPC or not.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data
 *  const uint16_t    - the TID to check
 *
 * Returns:
 *  bool - True if TID is IPC, false if not or if TID not found.
 *
 ********************************************************************/
static bool DCE2_SmbIsTidIPC(DCE2_SmbSsnData* ssd, const uint16_t tid)
{
    if ((ssd->tid != DCE2_SENTINEL)
        && ((ssd->tid & 0x0000ffff) == (int)tid))
    {
        if ((ssd->tid >> 16) == 0)
            return true;
    }
    else
    {
        int check_tid = (int)(uintptr_t)DCE2_ListFind(ssd->tids, (void*)(uintptr_t)tid);
        if (((check_tid & 0x0000ffff) == (int)tid) && ((check_tid >> 16) == 0))
            return true;
    }

    return false;
}

static DCE2_Ret DCE2_SmbInitFileTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker, const bool is_ipc, const uint16_t uid,
    const uint16_t tid, const int fid)
{
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    ftracker->uid = uid;
    ftracker->tid = tid;
    ftracker->fid = fid;
    ftracker->is_ipc = is_ipc;
    ftracker->file_name = nullptr;
    if (is_ipc)
    {
        DCE2_CoTracker* co_tracker = (DCE2_CoTracker*)snort_calloc(sizeof(DCE2_CoTracker));
        if (co_tracker == nullptr)
            return DCE2_RET__ERROR;
        DCE2_CoInitTracker(co_tracker);
        ftracker->fp_co_tracker = co_tracker;
        ftracker->fp_byte_mode = false;
        ftracker->fp_used = false;
        ftracker->fp_writex_raw = nullptr;
    }
    else
    {
        ftracker->ff_file_size = 0;
        ftracker->ff_file_offset = 0;
        ftracker->ff_bytes_processed = 0;
        ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UNKNOWN;
        ftracker->ff_file_chunks = nullptr;
        ftracker->ff_bytes_queued = 0;
        if ((ssd->fapi_ftracker == nullptr) && (ssd->max_file_depth != -1))
        {
            DebugFormat(DEBUG_DCE_SMB, "Designating file tracker "
                "for file API processing: 0x%04X\n", (uint16_t)fid);
            ssd->fapi_ftracker = ftracker;
        }
    }

    return DCE2_RET__SUCCESS;
}

static DCE2_SmbFileTracker* DCE2_SmbNewFileTracker(DCE2_SmbSsnData* ssd,
    const uint16_t uid, const uint16_t tid, const uint16_t fid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    // Already have tracker for file API and not setting file data pointer
    // so don't create new file tracker.
    bool is_ipc = DCE2_SmbIsTidIPC(ssd, tid);
    if (!is_ipc && (ssd->fapi_ftracker != nullptr)
        && (DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config) == -1))
        return nullptr;

    DebugFormat(DEBUG_DCE_SMB, "Creating new file tracker "
        "with Uid: %u, Tid: %u, Fid: 0x%04X\n", uid, tid, fid);

    DCE2_SmbFileTracker* ftracker = nullptr;
    if (ssd->ftracker.fid == DCE2_SENTINEL)
    {
        ftracker = &ssd->ftracker;
        if (DCE2_SmbInitFileTracker(ssd, ftracker, is_ipc, uid, tid, (int)fid) !=
            DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanFileTracker(ftracker);
            return nullptr;
        }
    }
    else
    {
        ftracker = (DCE2_SmbFileTracker*)snort_calloc(sizeof(DCE2_SmbFileTracker));

        if (ftracker == nullptr)
        {
            return nullptr;
        }

        if (DCE2_SmbInitFileTracker(ssd, ftracker, is_ipc, uid, tid, (int)fid) !=
            DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanFileTracker(ftracker);
            snort_free((void*)ftracker);
            return nullptr;
        }

        if (ssd->ftrackers == nullptr)
        {
            ssd->ftrackers = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED,
                DCE2_SmbUidTidFidCompare, DCE2_SmbFileTrackerDataFree, nullptr,
                DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->ftrackers == nullptr)
            {
                DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
                return nullptr;
            }
        }

        if (DCE2_ListInsert(ssd->ftrackers, (void*)(uintptr_t)fid,
            (void*)ftracker) != DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
            return nullptr;
        }
    }

    return ftracker;
}

static DCE2_SmbFileTracker* DCE2_SmbFindFileTracker(DCE2_SmbSsnData* ssd,
    const uint16_t uid, const uint16_t tid, const uint16_t fid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB, "Finding file tracker with "
        "Uid: %u, Tid: %u, Fid: 0x%04X ... ", uid, tid, fid);

    DCE2_SmbFileTracker* ftracker;
    if ((ssd->ftracker.fid != DCE2_SENTINEL) && (ssd->ftracker.fid == (int)fid))
    {
        ftracker = &ssd->ftracker;
    }
    else
    {
        ftracker = (DCE2_SmbFileTracker*)
            DCE2_ListFind(ssd->ftrackers, (void*)(uintptr_t)fid);
    }

    if (ftracker == nullptr)
    {
        DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
        return nullptr;
    }

    // Note IPC Tid has already been validated in initial processing
    const DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    switch (policy)
    {
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
        // Only Uid used to open file can be used to make a request
        if (ftracker->uid != uid)
        {
            DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
            return nullptr;
        }

        break;

    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__SAMBA_3_0_20:
    case DCE2_POLICY__SAMBA_3_0_22:
        // Any valid Uid can be used to make a request to a file ...
        // except for Windows 2000 on the first use.
        if ((policy != DCE2_POLICY__WIN2000) || (ftracker->is_ipc && ftracker->fp_used))
        {
            // Check that the Uid exists
            if (DCE2_SmbFindUid(ssd, uid) != DCE2_RET__SUCCESS)
            {
                DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
                return nullptr;
            }

            break;
        }

    // Fall through for Windows 2000 for first request to file

    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        // Both Uid and Tid used to create file must be used to make a request
        if ((ftracker->uid != uid) || (ftracker->tid != tid))
        {
            DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
            return nullptr;
        }

        break;

    default:
        DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
            __FILE__, __LINE__, policy);
        break;
    }

    DebugFormat(DEBUG_DCE_SMB, "Found with "
        "Uid: %u, Tid: %u, Fid: 0x%04X\n",
        ftracker->uid, ftracker->tid, ftracker->fid);
    return ftracker;
}

static DCE2_SmbFileTracker* DCE2_SmbGetFileTracker(DCE2_SmbSsnData* ssd,
    const uint16_t fid)
{
    DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;

    if (ftracker == nullptr)
    {
        // Write could've been chained to an OpenAndX or NtCreateAndX so a
        // temporary file tracker would've been created until we get the
        // response with the Fid returned from the OpenAndX / NtCreateAndX
        ftracker = DCE2_SmbGetTmpFileTracker(ssd->cur_rtracker);
        if (ftracker == nullptr)
        {
            // Otherwise find it with the passed in Fid
            ftracker = DCE2_SmbFindFileTracker(ssd, ssd->cur_rtracker->uid,
                ssd->cur_rtracker->tid, fid);
        }
    }

    return ftracker;
}

static DCE2_SmbFileTracker* DCE2_SmbGetTmpFileTracker(DCE2_SmbRequestTracker* rtracker)
{
    if (!DCE2_QueueIsEmpty(rtracker->ft_queue))
        return (DCE2_SmbFileTracker*)DCE2_QueueLast(rtracker->ft_queue);
    return nullptr;
}

static void DCE2_SmbRemoveFileTracker(DCE2_SmbSsnData* ssd, DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB,
        "Removing file tracker with Fid: 0x%04X\n", ftracker->fid);

    // FIXIT-M uncomment when file api related code is ported
    /*
    if (ssd->fapi_ftracker == ftracker)
        DCE2_SmbFinishFileAPI(ssd);
    */

    //FIXIT-M port active response related code
/*
#ifdef ACTIVE_RESPONSE
    if (ssd->fb_ftracker == ftracker)
        DCE2_SmbFinishFileBlockVerdict(ssd);
#endif
*/
    if (ftracker == &ssd->ftracker)
        DCE2_SmbCleanFileTracker(&ssd->ftracker);
    else if (ssd->ftrackers != nullptr)
        DCE2_ListRemove(ssd->ftrackers, (void*)(uintptr_t)ftracker->fid);

    DCE2_SmbRemoveFileTrackerFromRequestTrackers(ssd, ftracker);
}

static void DCE2_SmbCleanFileTracker(DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    Profile profile(dce2_smb_pstat_smb_fid);

    ftracker->fid = DCE2_SENTINEL;
    if (ftracker->file_name != nullptr)
    {
        snort_free((void*)ftracker->file_name);
        ftracker->file_name = nullptr;
    }

    if (ftracker->is_ipc)
    {
        ftracker->fp_used = 0;
        ftracker->fp_byte_mode = 0;

        if (ftracker->fp_writex_raw != nullptr)
        {
            DCE2_BufferDestroy(ftracker->fp_writex_raw->buf);
            snort_free((void*)ftracker->fp_writex_raw);
            ftracker->fp_writex_raw = nullptr;
        }

        if (ftracker->fp_co_tracker != nullptr)
        {
            DCE2_CoCleanTracker(ftracker->fp_co_tracker);
            snort_free((void*)ftracker->fp_co_tracker);
            ftracker->fp_co_tracker = nullptr;
        }
    }
    else
    {
        ftracker->ff_file_size = 0;
        ftracker->ff_file_offset = 0;
        ftracker->ff_bytes_processed = 0;
        ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UNKNOWN;
        ftracker->ff_bytes_queued = 0;
        ftracker->ff_sequential_only = false;
        if (ftracker->ff_file_chunks != nullptr)
        {
            DCE2_ListDestroy(ftracker->ff_file_chunks);
            ftracker->ff_file_chunks = nullptr;
        }
    }
}

static int DCE2_SmbUidTidFidCompare(const void* a, const void* b)
{
    int x = (int)(uintptr_t)a;
    int y = (int)(uintptr_t)b;

    if (x == y)
        return 0;

    /* Only care about equality for finding */
    return -1;
}

static DCE2_Ret DCE2_SmbFindUid(DCE2_SmbSsnData* ssd, const uint16_t uid)
{
    DCE2_Ret status;

    Profile profile(dce2_smb_pstat_smb_uid);

    if ((ssd->uid != DCE2_SENTINEL) && (ssd->uid == (int)uid))
        status = DCE2_RET__SUCCESS;
    else
        status = DCE2_ListFindKey(ssd->uids, (void*)(uintptr_t)uid);

    return status;
}

static void DCE2_SmbInsertUid(DCE2_SmbSsnData* ssd, const uint16_t uid)
{
    Profile profile(dce2_smb_pstat_smb_uid);

    DebugFormat(DEBUG_DCE_SMB, "Inserting Uid: %u\n", uid);

    if (ssd->uid == DCE2_SENTINEL)
    {
        ssd->uid = (int)uid;
    }
    else
    {
        if (ssd->uids == nullptr)
        {
            ssd->uids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_SmbUidTidFidCompare,
                nullptr, nullptr, DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->uids == nullptr)
            {
                return;
            }
        }

        DCE2_ListInsert(ssd->uids, (void*)(uintptr_t)uid, (void*)(uintptr_t)uid);
    }
}

static void DCE2_SmbRemoveUid(DCE2_SmbSsnData* ssd, const uint16_t uid)
{
    const DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);

    Profile profile(dce2_smb_pstat_smb_uid);

    DebugFormat(DEBUG_DCE_SMB,"Removing Uid: %u\n", uid);

    if ((ssd->uid != DCE2_SENTINEL) && (ssd->uid == (int)uid))
        ssd->uid = DCE2_SENTINEL;
    else
        DCE2_ListRemove(ssd->uids, (void*)(uintptr_t)uid);

    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
        // Removing uid invalidates any fid that was created with it */
        if ((ssd->ftracker.fid != DCE2_SENTINEL) &&
            (ssd->ftracker.uid == uid))
        {
            DCE2_SmbRemoveFileTracker(ssd, &ssd->ftracker);
        }

        if (ssd->ftrackers != nullptr)
        {
            DCE2_SmbFileTracker* ftracker;

            for (ftracker = (DCE2_SmbFileTracker*)DCE2_ListFirst(ssd->ftrackers);
                ftracker != nullptr;
                ftracker = (DCE2_SmbFileTracker*)DCE2_ListNext(ssd->ftrackers))
            {
                if (ftracker->uid == uid)
                {
// FIXIT-M uncomment after file api is ported
/*
                        if (ssd->fapi_ftracker == ftracker)
                            DCE2_SmbFinishFileAPI(ssd);

#ifdef ACTIVE_RESPONSE
                        if (ssd->fb_ftracker == ftracker)
                            DCE2_SmbFinishFileBlockVerdict(ssd);
#endif
*/
                    DCE2_ListRemoveCurrent(ssd->ftrackers);
                    DCE2_SmbRemoveFileTrackerFromRequestTrackers(ssd, ftracker);
                }
            }
        }

        break;

    case DCE2_POLICY__SAMBA_3_0_20:
    case DCE2_POLICY__SAMBA_3_0_22:
        // Removing Uid used to create file doesn't invalidate it.
        break;

    default:
        DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
            __FILE__, __LINE__, policy);
        break;
    }
}

static void DCE2_SmbFileTrackerDataFree(void* data)
{
    DCE2_SmbFileTracker* ftracker = (DCE2_SmbFileTracker*)data;

    if (ftracker == nullptr)
        return;

    DebugFormat(DEBUG_DCE_SMB, "Freeing file tracker: "
        "Uid: %u, Tid: %u, Fid: 0x%04X\n",
        ftracker->uid, ftracker->tid, ftracker->fid);

    DCE2_SmbCleanFileTracker(ftracker);
    snort_free((void*)ftracker);
}

/********************************************************************
 *
 * Remove file tracker and associated pointers in session
 *
 ********************************************************************/
static void DCE2_SmbCleanSessionFileTracker(DCE2_SmbSsnData* ssd, DCE2_SmbFileTracker* ftracker)
{
    DCE2_SmbCleanFileTracker(ftracker);
    snort_free((void*)ftracker);
    if (ssd->fapi_ftracker == ftracker)
        ssd->fapi_ftracker = nullptr;
}

static void DCE2_SmbCleanTransactionTracker(DCE2_SmbTransactionTracker* ttracker)
{
    Profile profile(dce2_smb_pstat_smb_req);

    if (ttracker == nullptr)
    {
        return;
    }

    if (ttracker->dbuf != nullptr)
        DCE2_BufferDestroy(ttracker->dbuf);

    if (ttracker->pbuf != nullptr)
        DCE2_BufferDestroy(ttracker->pbuf);

    memset(ttracker, 0, sizeof(*ttracker));
}

static void DCE2_SmbCleanRequestTracker(DCE2_SmbRequestTracker* rtracker)
{
    Profile profile(dce2_smb_pstat_smb_req);

    if (rtracker == nullptr)
    {
        return;
    }

    if (rtracker->mid == DCE2_SENTINEL)
    {
        return;
    }

    rtracker->mid = DCE2_SENTINEL;
    rtracker->ftracker = nullptr;
    rtracker->sequential_only = false;

    DCE2_SmbCleanTransactionTracker(&rtracker->ttracker);

    DCE2_QueueDestroy(rtracker->ft_queue);
    rtracker->ft_queue = nullptr;

    if (rtracker->file_name != nullptr)
    {
        snort_free((void*)rtracker->file_name);
        rtracker->file_name = nullptr;
    }
}

static inline void DCE2_SmbRemoveRequestTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbRequestTracker* rtracker)
{
    Profile profile(dce2_smb_pstat_smb_req);

    if ((ssd == nullptr) || (rtracker == nullptr))
    {
        return;
    }

    DebugFormat(DEBUG_DCE_SMB, "Removing request tracker => "
        "Uid: %u, Tid: %u, Pid: %u, Mid: %u ... ",
        rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid);

    if (rtracker == &ssd->rtracker)
    {
        DebugMessage(DEBUG_DCE_SMB, "Removed\n");

        DCE2_SmbCleanRequestTracker(&ssd->rtracker);
        ssd->outstanding_requests--;
        return;
    }

    DCE2_SmbRequestTracker* tmp_node;
    for (tmp_node = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        tmp_node != nullptr;
        tmp_node = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers))
    {
        if (tmp_node == (void*)rtracker)
        {
            DebugMessage(DEBUG_DCE_SMB, "Removed\n");

            DCE2_QueueRemoveCurrent(ssd->rtrackers);
            ssd->outstanding_requests--;
            return;
        }
    }

    DebugMessage(DEBUG_DCE_SMB, "Not removed.\n");
}

static void DCE2_SmbRemoveFileTrackerFromRequestTrackers(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    // NULL out file trackers of any outstanding requests
    // that reference this file tracker
    if (ssd->rtracker.ftracker == ftracker)
        ssd->rtracker.ftracker = nullptr;

    if ((ssd->cur_rtracker != nullptr) && (ssd->cur_rtracker->ftracker == ftracker))
        ssd->cur_rtracker->ftracker = nullptr;

    DCE2_SmbRequestTracker* rtracker;
    for (rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        rtracker != nullptr;
        rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers))
    {
        if (rtracker->ftracker == ftracker)
            rtracker->ftracker = nullptr;
    }
}

static DCE2_SmbFileTracker* DCE2_SmbDequeueTmpFileTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbRequestTracker* rtracker, const uint16_t fid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB, "Dequeueing file tracker "
        "and binding to fid: 0x%04X\n", fid);

    DCE2_SmbFileTracker* ftracker = (DCE2_SmbFileTracker*)DCE2_QueueDequeue(rtracker->ft_queue);

    if (ftracker == nullptr)
    {
        return nullptr;
    }

    if (ssd->ftracker.fid == DCE2_SENTINEL)
    {
        memcpy(&ssd->ftracker, ftracker, sizeof(DCE2_SmbFileTracker));
        snort_free((void*)ftracker);
        if (ssd->fapi_ftracker == ftracker)
            ssd->fapi_ftracker = &ssd->ftracker;
        ftracker = &ssd->ftracker;
    }
    else
    {
        if (ssd->ftrackers == nullptr)
        {
            ssd->ftrackers = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED,
                DCE2_SmbUidTidFidCompare, DCE2_SmbFileTrackerDataFree, nullptr,
                DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->ftrackers == nullptr)
            {
                DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
                return nullptr;
            }
        }

        if (DCE2_ListInsert(ssd->ftrackers, (void*)(uintptr_t)fid,
            (void*)ftracker) != DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
            return nullptr;
        }
    }

    // Other values were intialized when queueing.
    ftracker->fid = (int)fid;

    return ftracker;
}

static void DCE2_SmbRequestTrackerDataFree(void* data)
{
    DCE2_SmbRequestTracker* rtracker = (DCE2_SmbRequestTracker*)data;

    if (rtracker == nullptr)
        return;

    DebugFormat(DEBUG_DCE_SMB, "Freeing request tracker: "
        "Uid: %u, Tid: %u, Pid: %u, Mid: %u\n",
        rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid);

    DCE2_SmbCleanRequestTracker(rtracker);
    snort_free((void*)rtracker);
}

static DCE2_Ret DCE2_SmbFindTid(DCE2_SmbSsnData* ssd, const uint16_t tid)
{
    DCE2_Ret status;

    Profile profile(dce2_smb_pstat_smb_tid);

    if ((ssd->tid != DCE2_SENTINEL) && ((ssd->tid & 0x0000ffff) == (int)tid))
        status = DCE2_RET__SUCCESS;
    else
        status = DCE2_ListFindKey(ssd->tids, (void*)(uintptr_t)tid);

    return status;
}

static void DCE2_SmbRemoveTid(DCE2_SmbSsnData* ssd, const uint16_t tid)
{
    Profile profile(dce2_smb_pstat_smb_tid);

    DebugFormat(DEBUG_DCE_SMB, "Removing Tid: %u\n", tid);

    if ((ssd->tid != DCE2_SENTINEL) && ((ssd->tid & 0x0000ffff) == (int)tid))
        ssd->tid = DCE2_SENTINEL;
    else
        DCE2_ListRemove(ssd->tids, (void*)(uintptr_t)tid);

    // Removing Tid invalidates files created with it
    if ((ssd->ftracker.fid != DCE2_SENTINEL)
        && (ssd->ftracker.tid == tid))
    {
        DCE2_SmbRemoveFileTracker(ssd, &ssd->ftracker);
    }

    if (ssd->ftrackers != nullptr)
    {
        DCE2_SmbFileTracker* ftracker;

        for (ftracker = (DCE2_SmbFileTracker*)DCE2_ListFirst(ssd->ftrackers);
            ftracker != nullptr;
            ftracker = (DCE2_SmbFileTracker*)DCE2_ListNext(ssd->ftrackers))
        {
            if (ftracker->tid == (int)tid)
            {
// FIXIT-M uncomment once file api is ported
/*
                if (ssd->fapi_ftracker == ftracker)
                    DCE2_SmbFinishFileAPI(ssd);

#ifdef ACTIVE_RESPONSE
                if (ssd->fb_ftracker == ftracker)
                    DCE2_SmbFinishFileBlockVerdict(ssd);
#endif
*/
                DCE2_ListRemoveCurrent(ssd->ftrackers);
                DCE2_SmbRemoveFileTrackerFromRequestTrackers(ssd, ftracker);
            }
        }
    }
}

static void DCE2_SmbInsertTid(DCE2_SmbSsnData* ssd,
    const uint16_t tid, const bool is_ipc)
{
    Profile profile(dce2_smb_pstat_smb_tid);

    if (!is_ipc && (!DCE2_ScSmbFileInspection((dce2SmbProtoConf*)ssd->sd.config)
        || ((ssd->max_file_depth == -1) && DCE2_ScSmbFileDepth(
        (dce2SmbProtoConf*)ssd->sd.config) == -1)))
    {
        DebugFormat(DEBUG_DCE_SMB, "Not inserting TID (%u) "
            "because it's not IPC and not inspecting normal file "
            "data.", tid);
        return;
    }

    if (is_ipc && DCE2_ScSmbFileInspectionOnly((dce2SmbProtoConf*)ssd->sd.config))
    {
        DebugFormat(DEBUG_DCE_SMB, "Not inserting TID (%u) "
            "because it's IPC and only inspecting normal file "
            "data.", tid);
        return;
    }

    DebugFormat(DEBUG_DCE_SMB, "Inserting Tid: %u\n", tid);
    int insert_tid = (int)tid;
    // Set a bit so as to distinguish between IPC and non-IPC TIDs
    if (!is_ipc)
        insert_tid |= (1 << 16);

    if (ssd->tid == DCE2_SENTINEL)
    {
        ssd->tid = insert_tid;
    }
    else
    {
        if (ssd->tids == nullptr)
        {
            ssd->tids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_SmbUidTidFidCompare,
                nullptr, nullptr, DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->tids == nullptr)
            {
                return;
            }
        }

        DCE2_ListInsert(ssd->tids, (void*)(uintptr_t)tid, (void*)(uintptr_t)insert_tid);
    }
}

static DCE2_SmbRequestTracker* DCE2_SmbFindRequestTracker(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr)
{
    uint16_t uid = SmbUid(smb_hdr);
    uint16_t tid = SmbTid(smb_hdr);
    uint16_t pid = SmbPid(smb_hdr);
    uint16_t mid = SmbMid(smb_hdr);

    Profile profile(dce2_smb_pstat_smb_req);

    DebugFormat(DEBUG_DCE_SMB, "Find request tracker => "
        "Uid: %u, Tid: %u, Pid: %u, Mid: %u ... ", uid, tid, pid, mid);

    DCE2_SmbRequestTracker* tmp_rtracker = &ssd->rtracker;
    int smb_com = SmbCom(smb_hdr);
    switch (smb_com)
    {
    case SMB_COM_TRANSACTION_SECONDARY:
        smb_com = SMB_COM_TRANSACTION;
        break;
    case SMB_COM_TRANSACTION2_SECONDARY:
        smb_com = SMB_COM_TRANSACTION2;
        break;
    case SMB_COM_NT_TRANSACT_SECONDARY:
        smb_com = SMB_COM_NT_TRANSACT;
        break;
    case SMB_COM_WRITE_COMPLETE:
        smb_com = SMB_COM_WRITE_RAW;
        break;
    default:
        break;
    }

    DCE2_SmbRequestTracker* first_rtracker = nullptr;
    DCE2_SmbRequestTracker* win_rtracker = nullptr;
    DCE2_SmbRequestTracker* first_mid_rtracker = nullptr;
    DCE2_SmbRequestTracker* ret_rtracker = nullptr;
    while (tmp_rtracker != nullptr)
    {
        if ((tmp_rtracker->mid == (int)mid) && (tmp_rtracker->smb_com == smb_com))
        {
            // This is the normal case except for SessionSetupAndX and
            // TreeConnect/TreeConnectAndX which will fall into the
            // default case below.
            if ((tmp_rtracker->pid == pid) && (tmp_rtracker->uid == uid)
                && (tmp_rtracker->tid == tid))
            {
                ret_rtracker = tmp_rtracker;
            }
            else
            {
                switch (smb_com)
                {
                case SMB_COM_TRANSACTION:
                case SMB_COM_TRANSACTION2:
                case SMB_COM_NT_TRANSACT:
                case SMB_COM_TRANSACTION_SECONDARY:
                case SMB_COM_TRANSACTION2_SECONDARY:
                case SMB_COM_NT_TRANSACT_SECONDARY:
                    // These should conform to above
                    break;
                default:
                    if (tmp_rtracker->pid == pid)
                        ret_rtracker = tmp_rtracker;
                    break;
                }
            }

            if (ret_rtracker != nullptr)
            {
                DebugMessage(DEBUG_DCE_SMB, "Found.\n");
                return ret_rtracker;
            }

            // Take the first one where the PIDs also match
            // in the case of the Transacts above
            if ((tmp_rtracker->pid == pid) && (win_rtracker == nullptr))
                win_rtracker = tmp_rtracker;

            // Set this to the first matching request in the queue
            // where the Mid matches.  Don't set for Windows if from
            // client since PID/MID are necessary
            if (((DCE2_SmbType(ssd) == SMB_TYPE__RESPONSE)
                || !DCE2_SsnIsWindowsPolicy(&ssd->sd))
                && first_mid_rtracker == nullptr)
            {
                first_mid_rtracker = tmp_rtracker;
            }
        }

        // Set the first one we see for early Samba versions
        if ((first_rtracker == nullptr) && (tmp_rtracker->mid != DCE2_SENTINEL)
            && (tmp_rtracker->smb_com == smb_com))
            first_rtracker = tmp_rtracker;

        // Look at the next request in the queue
        if (tmp_rtracker == &ssd->rtracker)
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        else
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers);
    }

    DCE2_Policy policy = DCE2_SsnGetPolicy(&ssd->sd);
    switch (policy)
    {
    case DCE2_POLICY__SAMBA_3_0_20:
    case DCE2_POLICY__SAMBA_3_0_22:
        ret_rtracker = first_rtracker;
        break;
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
        ret_rtracker = first_mid_rtracker;
        break;
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        if (win_rtracker != nullptr)
            ret_rtracker = win_rtracker;
        else
            ret_rtracker = first_mid_rtracker;
        break;
    default:
        DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
            __FILE__, __LINE__, policy);
        break;
    }

    return ret_rtracker;
}

static DCE2_SmbRequestTracker* DCE2_SmbNewRequestTracker(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr)
{
    uint16_t pid = SmbPid(smb_hdr);
    uint16_t mid = SmbMid(smb_hdr);
    uint16_t uid = SmbUid(smb_hdr);
    uint16_t tid = SmbTid(smb_hdr);

    Profile profile(dce2_smb_pstat_smb_req);

    if (ssd == nullptr)
    {
        return nullptr;
    }

    if (ssd->outstanding_requests >= ssd->max_outstanding_requests)
    {
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats);
    }

    // Check for outstanding requests with the same MID
    DCE2_SmbRequestTracker* tmp_rtracker = &ssd->rtracker;
    while ((tmp_rtracker != nullptr) && (tmp_rtracker->mid != DCE2_SENTINEL))
    {
        if (tmp_rtracker->mid == (int)mid)
        {
            // Have yet to see an MID repeatedly used so shouldn't
            // be any outstanding requests with the same MID.
            dce_alert(GID_DCE2, DCE2_SMB_REQS_SAME_MID, (dce2CommonStats*)&dce2_smb_stats);
            break;
        }

        // Look at the next request in the queue
        if (tmp_rtracker == &ssd->rtracker)
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        else
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers);
    }

    DCE2_SmbRequestTracker* rtracker = nullptr;
    if (ssd->rtracker.mid == DCE2_SENTINEL)
    {
        rtracker = &ssd->rtracker;
    }
    else
    {
        if (ssd->rtrackers == nullptr)
        {
            ssd->rtrackers = DCE2_QueueNew(DCE2_SmbRequestTrackerDataFree);
            if (ssd->rtrackers == nullptr)
            {
                return nullptr;
            }
        }

        rtracker = (DCE2_SmbRequestTracker*)snort_calloc(sizeof(DCE2_SmbRequestTracker));
        if (rtracker == nullptr)
        {
            return nullptr;
        }

        if (DCE2_QueueEnqueue(ssd->rtrackers, (void*)rtracker) != DCE2_RET__SUCCESS)
        {
            snort_free((void*)rtracker);
            return nullptr;
        }
    }

    rtracker->smb_com = SmbCom(smb_hdr);
    rtracker->uid = uid;
    rtracker->tid = tid;
    rtracker->pid = pid;
    rtracker->mid = (int)mid;
    memset(&rtracker->ttracker, 0, sizeof(rtracker->ttracker));
    rtracker->ftracker = nullptr;
    rtracker->sequential_only = false;

    ssd->outstanding_requests++;
    if (ssd->outstanding_requests > dce2_smb_stats.smb_max_outstanding_requests)
        dce2_smb_stats.smb_max_outstanding_requests = ssd->outstanding_requests;

    DebugFormat(DEBUG_DCE_SMB, "Added new request tracker => "
        "Uid: %u, Tid: %u, Pid: %u, Mid: %u\n",
        rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid);
    DebugFormat(DEBUG_DCE_SMB,
        "Current outstanding requests: %u\n", ssd->outstanding_requests);

    return rtracker;
}

static DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData* ssd,
    const uint16_t fid, const uint8_t* data_ptr, uint32_t data_len, uint64_t offset)
{
    DCE2_SmbFileTracker* ftracker = DCE2_SmbGetFileTracker(ssd, fid);

    DebugFormat(DEBUG_DCE_SMB,
        "Entering Processing request data with Fid: 0x%04X, ftracker ? %s ~~~~~~~~~~~~~~~~~\n",
        fid,ftracker ? "TRUE" : "FALSE");
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    DebugFormat(DEBUG_DCE_SMB,
        "Processing request data with Fid: 0x%04X, is_ipc ? %s ~~~~~~~~~~~~~~~~~\n", ftracker->fid,
        ftracker->is_ipc ? "TRUE" : "FALSE");

    // Set this in case of chained commands or reassembled packet
    ssd->cur_rtracker->ftracker = ftracker;

    if (ftracker->is_ipc)
    {
        // Maximum possible fragment length is 16 bit
        if (data_len > UINT16_MAX)
            data_len = UINT16_MAX;

        DCE2_CoProcess(&ssd->sd, ftracker->fp_co_tracker, data_ptr, (uint16_t)data_len);

        if (!ftracker->fp_used)
            ftracker->fp_used = true;
    }
    else
    {
        ftracker->ff_file_offset = offset;
        // FIXIT-M uncomment when file processing is ported
        // DCE2_SmbProcessFileData(ssd, ftracker, data_ptr, data_len, true);
    }

    DebugMessage(DEBUG_DCE_SMB, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

    return DCE2_RET__SUCCESS;
}

static DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData* ssd,
    const uint8_t* data_ptr, uint32_t data_len)
{
    DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;

    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    DebugFormat(DEBUG_DCE_SMB,
        "Processing response data with Fid: 0x%04X ~~~~~~~~~~~~~~~~\n", ftracker->fid);

    if (ftracker->is_ipc)
    {
        // Maximum possible fragment length is 16 bit
        if (data_len > UINT16_MAX)
            data_len = UINT16_MAX;

        DCE2_CoProcess(&ssd->sd, ftracker->fp_co_tracker, data_ptr, (uint16_t)data_len);
    }
    else
    {
        ftracker->ff_file_offset = ssd->cur_rtracker->file_offset;
        // FIXIT-M uncomment when file processing is ported
        //DCE2_SmbProcessFileData(ssd, ftracker, data_ptr, data_len, false);
    }

    DebugMessage(DEBUG_DCE_SMB, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbHdrChecks()
 *
 * Checks some relevant fields in the header to make sure they're
 * sane.
 * Side effects are potential alerts for anomolous behavior.
 *
 * Arguments:
 *  DCE2_SmbSsnData *
 *      Pointer to the session data structure.
 *  SmbNtHdr *
 *      Pointer to the header struct layed over the packet data.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__IGNORE if we should continue processing, but
 *          ignore data because of the error.
 *      DCE2_RET__SUCCESS if we should continue processing.
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbHdrChecks(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr)
{
    Packet* p = ssd->sd.wire_pkt;

    if ((DCE2_SsnFromServer(p) && (SmbType(smb_hdr) == SMB_TYPE__REQUEST)) ||
        (DCE2_SsnFromClient(p) && (SmbType(smb_hdr) == SMB_TYPE__RESPONSE)))
    {
        // FIXIT-M port segment check
        // Same for all cases below
        dce_alert(GID_DCE2, DCE2_SMB_BAD_TYPE, (dce2CommonStats*)&dce2_smb_stats);
        // Continue looking at traffic.  Neither Windows nor Samba seem
        // to care, or even look at this flag
    }

    if ((SmbId(smb_hdr) != DCE2_SMB_ID)
        && (SmbId(smb_hdr) != DCE2_SMB2_ID))
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_ID, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__IGNORE;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbGetMinByteCount()
 *
 * Purpose:
 *  Returns the minimum byte count for the given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *
 * Returns:
 *  uint16_t - the minimum byte count
 *
 ********************************************************************/
static inline uint16_t DCE2_SmbGetMinByteCount(uint8_t com, uint8_t resp)
{
    return smb_bccs[com][resp][0];
}

/********************************************************************
 * Function: DCE2_SmbGetString()
 *
 * Purpose:
 *  Parses data passed in and returns an ASCII string.  True
 *  unicode characters are replaced with a '.'
 *
 * Arguments:
 *  const uint8_t *  - pointer to data
 *  uint32_t         - data length
 *  bool             - true if the data is unicode (UTF-16LE)
 *  bool             - true if the function should only return the
 *                     file name instead of the entire path
 *
 * Returns:
 *  char *  - NULL terminated ASCII string
 *
 ********************************************************************/
static char* DCE2_SmbGetString(const uint8_t* data,
    uint32_t data_len, bool unicode, bool get_file)
{
    char* str;
    uint32_t i, j, k = unicode ? data_len - 1 : data_len;
    uint8_t inc = unicode ? 2 : 1;

    if (data_len < inc)
        return nullptr;

    // Move forward.  Don't know if the end of data is actually
    // the end of the string.
    for (i = 0, j = 0; i < k; i += inc)
    {
        uint16_t uchar = unicode ? extract_16bits(data + i) : data[i];

        if (uchar == 0)
            break;
        else if (get_file && ((uchar == 0x002F) || (uchar == 0x005C)))  // slash and back-slash
            j = i + inc;
    }

    // Only got a NULL byte or nothing after slash/back-slash or too big.
    if ((i == 0) || (j == i)
        || (get_file && (i > DCE2_SMB_MAX_COMP_LEN))
        || (i > DCE2_SMB_MAX_PATH_LEN))
        return nullptr;

    str = (char*)snort_calloc(((i-j)>>(inc-1))+1);
    if (str == nullptr)
        return nullptr;

    for (k = 0; j < i; j += inc, k++)
    {
        if (isprint((int)data[j]))
            str[k] = (char)data[j];
        else
            str[k] = '.';
    }

    str[k] = 0;

    return str;
}

/********************************************************************
 * Function: DCE2_SmbCheckCommand()
 *
 * Purpose:
 *  Checks basic validity of an SMB command.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t           - the SMB command code, i.e. SMB_COM_*
 *  uint8_t *         - current pointer to data, i.e. the command
 *  uint32_t          - the remaining length
 *  DCE2_SmbComInfo & -
 *      Populated structure for command processing
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_SmbCheckCommand(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const uint8_t smb_com,
    const uint8_t* nb_ptr, uint32_t nb_len, DCE2_SmbComInfo& com_info)
{
    // Check for server error response
    if (com_info.smb_type == SMB_TYPE__RESPONSE)
    {
        const SmbEmptyCom* ec = (SmbEmptyCom*)nb_ptr;

        // Verify there is enough data to do checks
        if (nb_len < sizeof(SmbEmptyCom))
        {
            dce_alert(GID_DCE2, DCE2_SMB_NB_LT_COM, (dce2CommonStats*)&dce2_smb_stats);
            com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
            return;
        }

        // If word and byte counts are zero and there is an error
        // the server didn't accept client request
        if ((SmbEmptyComWct(ec) == 0)
            && (SmbEmptyComBcc(ec) == 0) && SmbError(smb_hdr))
        {
            DebugFormat(DEBUG_DCE_SMB,
                "Response error: 0x%08X\n", SmbNtStatus(smb_hdr));

            // If broken pipe, clean up data associated with open named pipe
            if (SmbBrokenPipe(smb_hdr))
            {
                DebugMessage(DEBUG_DCE_SMB, "Broken or disconnected pipe.\n");
                DCE2_SmbRemoveFileTracker(ssd, ssd->cur_rtracker->ftracker);
            }

            com_info.cmd_error |= DCE2_SMB_COM_ERROR__STATUS_ERROR;
            return;
        }
    }

    // Set the header size to the minimum size the command can be
    // without the byte count to make sure there is enough data to
    // get the word count.
    SmbAndXCom andx_com = smb_chain_map[smb_com];
    int chk_com_size;
    if (andx_com == SMB_ANDX_COM__NONE)
        chk_com_size = sizeof(SmbCommon);
    else
        chk_com_size = sizeof(SmbAndXCommon);

    // Verify there is enough data to do checks
    if (nb_len < (uint32_t)chk_com_size)
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_COM, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
        return;
    }

    const SmbCommon* sc = (SmbCommon*)nb_ptr;
    com_info.word_count = SmbWct(sc);

    // Make sure the word count is a valid one for the command.  If not
    // testing shows an error will be returned.  And command structures
    // won't lie on data correctly and out of bounds data accesses are possible.
    if (!DCE2_SmbIsValidWordCount(smb_com, (uint8_t)com_info.smb_type, com_info.word_count))
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_WCT, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT;
        return;
    }

    // This gets the size of the SMB command from word count through byte count
    // using the advertised value in the word count field.
    com_info.cmd_size = (uint16_t)SMB_COM_SIZE(com_info.word_count);
    if (nb_len < com_info.cmd_size)
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_COM, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
        return;
    }

    uint16_t smb_bcc = SmbBcc(nb_ptr, com_info.cmd_size);

    // SMB_COM_NT_CREATE_ANDX is a special case.  Who know what's going
    // on with the word count (see MS-CIFS and MS-SMB).  A 42 word count
    // command seems to actually have 50 words, so who knows where the
    // byte count is.  Just set to zero since it's not needed.
    if ((smb_com == SMB_COM_NT_CREATE_ANDX)
        && (com_info.smb_type == SMB_TYPE__RESPONSE))
        smb_bcc = 0;

    // If byte count is deemed invalid, alert but continue processing
    switch (smb_com)
    {
    // Interim responses
    case SMB_COM_TRANSACTION:
    case SMB_COM_TRANSACTION2:
    case SMB_COM_NT_TRANSACT:
        // If word count is 0, byte count must be 0
        if ((com_info.word_count == 0) && (com_info.smb_type == SMB_TYPE__RESPONSE))
        {
            if (smb_bcc != 0)
            {
                dce_alert(GID_DCE2, DCE2_SMB_BAD_BCC, (dce2CommonStats*)&dce2_smb_stats);
                com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT;
            }
            break;
        }
    // Fall through
    default:
        if (!DCE2_SmbIsValidByteCount(smb_com, (uint8_t)com_info.smb_type, smb_bcc))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_BCC, (dce2CommonStats*)&dce2_smb_stats);
            com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT;
        }
        break;
    }

    // Move just past byte count field which is the end of the command
    DCE2_MOVE(nb_ptr, nb_len, com_info.cmd_size);

    // Validate that there is enough data to be able to process the command
    if (nb_len < DCE2_SmbGetMinByteCount(smb_com, (uint8_t)com_info.smb_type))
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_BCC, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
    }

    // The byte count seems to be ignored by Windows and current Samba (3.5.4)
    // as long as it is less than the amount of data left.  If more, an error
    // is returned.
    // !!!WARNING!!! the byte count should probably never be used.
    if (smb_bcc > nb_len)
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_BCC, (dce2CommonStats*)&dce2_smb_stats);
        // Large byte count doesn't seem to matter for early Samba
        switch (DCE2_SsnGetPolicy(&ssd->sd))
        {
        case DCE2_POLICY__SAMBA_3_0_20:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_37:
            break;
        default:
            com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
            break;
        }
    }
    else if ((smb_bcc == 0) && (SmbCom(smb_hdr) == SMB_COM_TRANSACTION)
        && (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
        && (DCE2_SsnGetPolicy(&ssd->sd) == DCE2_POLICY__SAMBA))
    {
        // Current Samba errors on a zero byte count Transaction because it
        // uses it to get the Name string and if zero Name will be NULL and
        // it won't process it.
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
    }

    com_info.byte_count = smb_bcc;
}

/********************************************************************
 * Function: DCE2_SmbProcessCommand()
 *
 * Purpose:
 *  This is the main function for handling SMB commands and command
 *  chaining.
 *  It does an initial check of the command to determine validity
 *  and gets basic information about the command.  Then it calls the
 *  specific command function (setup in DCE2_SmbInitGlobals).
 *  If there is command chaining, it will do the chaining foo to
 *  get to the next command.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t *         - current pointer to data, i.e. the command
 *  uint32_t          - the remaining length
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_SmbProcessCommand(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint8_t smb_com = SmbCom(smb_hdr);
    DCE2_Ret status = DCE2_RET__ERROR;
    bool sess_chain = false;
    bool tree_chain = false;
    bool open_chain = false;
    int num_chained = 0;

    while (nb_len > 0)
    {
        // Break out if command not supported
        if (smb_com_funcs[smb_com] == nullptr)
            break;

        if (smb_deprecated_coms[smb_com])
        {
            dce_alert(GID_DCE2, DCE2_SMB_DEPR_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
        }

        if (smb_unusual_coms[smb_com])
        {
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
        }

        DCE2_SmbComInfo com_info;
        com_info.smb_type = DCE2_SmbType(ssd);
        com_info.cmd_error = DCE2_SMB_COM_ERROR__COMMAND_OK;
        com_info.word_count = 0;
        com_info.smb_com = smb_com;
        com_info.cmd_size = 0;
        com_info.byte_count = 0;
        DCE2_SmbCheckCommand(ssd, smb_hdr, smb_com, nb_ptr, nb_len, com_info);
        DebugFormat(DEBUG_DCE_SMB, "Processing command: %s (0x%02X)\n",
            smb_com_strings[smb_com], smb_com);

        // Note that even if the command shouldn't be processed, some of
        // the command functions need to know and do cleanup or some other
        // processing.
        status = smb_com_funcs[smb_com](ssd, smb_hdr,
                &com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__SUCCESS)
            break;

        // This command is not chainable
        SmbAndXCom andx_com = smb_chain_map[smb_com];
        if (andx_com == SMB_ANDX_COM__NONE)
            break;

        /**********************************************************
         * AndX Chaining
         **********************************************************/
        const SmbAndXCommon* andx_ptr = (SmbAndXCommon*)nb_ptr;
        uint8_t smb_com2 = SmbAndXCom2(andx_ptr);
        if (smb_com2 == SMB_COM_NO_ANDX_COMMAND)
            break;

        DebugFormat(DEBUG_DCE_SMB, "Chained SMB command: %s\n", smb_com_strings[smb_com2]);

        num_chained++;
        if (DCE2_ScSmbMaxChain((dce2SmbProtoConf*)ssd->sd.config) &&
            (num_chained >= DCE2_ScSmbMaxChain((dce2SmbProtoConf*)ssd->sd.config)))
        {
            dce_alert(GID_DCE2, DCE2_SMB_EXCESSIVE_CHAINING, (dce2CommonStats*)&dce2_smb_stats);
        }

        // Multiple SessionSetupAndX, TreeConnectAndX, OpenAndX and NtCreateAndX
        // are only allowed by Samba.
        if (smb_com == SMB_COM_SESSION_SETUP_ANDX)
            sess_chain = true;

        // Check for multiple chained SessionSetupAndX
        if ((smb_com2 == SMB_COM_SESSION_SETUP_ANDX) && sess_chain)
        {
            // There is only one place to return a uid.
            dce_alert(GID_DCE2, DCE2_SMB_MULT_CHAIN_SS, (dce2CommonStats*)&dce2_smb_stats);
            // FIXIT-L Should we continue processing?
            break;
        }

        // Check for chained SessionSetupAndX => .? => LogoffAndX
        if ((smb_com2 == SMB_COM_LOGOFF_ANDX) && sess_chain)
        {
            // This essentially deletes the uid created by the login
            // and doesn't make any sense.
            dce_alert(GID_DCE2, DCE2_SMB_CHAIN_SS_LOGOFF, (dce2CommonStats*)&dce2_smb_stats);
        }

        if (smb_com == SMB_COM_TREE_CONNECT_ANDX)
            tree_chain = true;

        // Check for multiple chained TreeConnects
        if (((smb_com2 == SMB_COM_TREE_CONNECT_ANDX)
            || (smb_com2 == SMB_COM_TREE_CONNECT)) && tree_chain)
        {
            // There is only one place to return a tid.
            dce_alert(GID_DCE2, DCE2_SMB_MULT_CHAIN_TC, (dce2CommonStats*)&dce2_smb_stats);
            // FIXIT-L Should we continue processing?
            break;
        }

        // Check for chained TreeConnectAndX => .? => TreeDisconnect
        if ((smb_com2 == SMB_COM_TREE_DISCONNECT) && tree_chain)
        {
            // This essentially deletes the tid created by the tree connect
            // and doesn't make any sense.
            dce_alert(GID_DCE2, DCE2_SMB_CHAIN_TC_TDIS, (dce2CommonStats*)&dce2_smb_stats);
        }

        if ((smb_com == SMB_COM_OPEN_ANDX) || (smb_com == SMB_COM_NT_CREATE_ANDX))
            open_chain = true;

        // Check for chained OpenAndX/NtCreateAndX => .? => Close
        if ((smb_com2 == SMB_COM_CLOSE) && open_chain)
        {
            // This essentially deletes the fid created by the open command
            // and doesn't make any sense.
            dce_alert(GID_DCE2, DCE2_SMB_CHAIN_OPEN_CLOSE, (dce2CommonStats*)&dce2_smb_stats);
        }

        // Check that policy allows for such chaining
        DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
        if (smb_chain_funcs[policy][andx_com][smb_com2] == nullptr)
            break;

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(&com_info));

        // FIXIT-L Need to test out of order chaining
        const uint8_t* off2_ptr = (uint8_t*)smb_hdr + SmbAndXOff2(andx_ptr);
        if (DCE2_SmbCheckAndXOffset(off2_ptr, nb_ptr, nb_len) != DCE2_RET__SUCCESS)
            break;

        DCE2_MOVE(nb_ptr, nb_len, (off2_ptr - nb_ptr));

        // FIXIT Need to test more.
        switch (smb_com)
        {
        case SMB_COM_SESSION_SETUP_ANDX:
        case SMB_COM_TREE_CONNECT_ANDX:
        case SMB_COM_OPEN_ANDX:
        case SMB_COM_NT_CREATE_ANDX:
            switch (smb_com2)
            {
            case SMB_COM_WRITE:
            case SMB_COM_WRITE_ANDX:
            case SMB_COM_TRANSACTION:
            case SMB_COM_READ_ANDX:
                if (DCE2_SsnFromClient(ssd->sd.wire_pkt) && open_chain)
                {
                    DCE2_SmbQueueTmpFileTracker(ssd, ssd->cur_rtracker,
                        SmbUid(smb_hdr), SmbTid(smb_hdr));
                }
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }

        smb_com = smb_com2;
    }

    int smb_type = DCE2_SmbType(ssd);
    if (smb_type == SMB_TYPE__RESPONSE)
    {
        switch (smb_com)
        {
        case SMB_COM_TRANSACTION:
        case SMB_COM_TRANSACTION2:
        case SMB_COM_NT_TRANSACT:
        case SMB_COM_TRANSACTION_SECONDARY:
        case SMB_COM_TRANSACTION2_SECONDARY:
        case SMB_COM_NT_TRANSACT_SECONDARY:
            // This case means there was an error with the initial response
            // so the tracker isn't yet officially in response mode
            if (ssd->cur_rtracker->ttracker.smb_type == SMB_TYPE__REQUEST)
            {
                // Samba throws out entire transaction and Windows just this request
                if (DCE2_SsnIsServerSambaPolicy(&ssd->sd) && (status != DCE2_RET__SUCCESS))
                    break;

                if (!DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                    return;
            }
            else
            {
                if ((status == DCE2_RET__SUCCESS)
                    && !DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                    return;
            }
            break;
        case SMB_COM_WRITE_RAW:
            if ((status == DCE2_RET__SUCCESS)
                && (ssd->cur_rtracker->writeraw_remaining != 0))
                return;
            break;
        default:
            break;
        }
    }
    else if (status != DCE2_RET__IGNORE)
    {
        switch (smb_com)
        {
        case SMB_COM_TRANSACTION:
        case SMB_COM_TRANSACTION_SECONDARY:
            if (DCE2_SsnIsWindowsPolicy(&ssd->sd))
            {
                if (!ssd->cur_rtracker->ttracker.one_way
                    || !DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                    return;

                // Remove the request tracker if transaction is one-way and
                // all data and parameters have been sent
                break;
            }
        default:
            // Anything else, keep the request tracker
            return;
        }
    }

    DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
    ssd->cur_rtracker = nullptr;
}

/********************************************************************
 * Function: DCE2_SmbInspect()
 *
 * Purpose:
 *  Determines whether the SMB command is something the preprocessor
 *  needs to inspect.
 *  This function returns a DCE2_SmbRequestTracker which tracks command
 *  requests / responses.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  const SmbNtHdr *  - pointer to the SMB header.
 *
 * Returns:
 *  DCE2_SmbRequestTracker * - nullptr if it's not something we want to or can
 *                     inspect.
 *                     Otherwise an initialized structure if request
 *                     and the found structure if response.
 *
 ********************************************************************/
static DCE2_SmbRequestTracker* DCE2_SmbInspect(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr)
{
    int smb_com = SmbCom(smb_hdr);

    DebugFormat(DEBUG_DCE_SMB, "SMB command: %s (0x%02X)\n",
        smb_com_strings[smb_com], smb_com);

    if (smb_com_funcs[smb_com] == nullptr)
    {
        DebugMessage(DEBUG_DCE_SMB, "Command isn't processed "
            "by preprocessor.\n");
        return nullptr;
    }

    // See if this is something we need to inspect
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    DCE2_SmbRequestTracker* rtracker = nullptr;
    if (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
    {
        switch (smb_com)
        {
        case SMB_COM_NEGOTIATE:
            if (ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__NEGOTIATED)
            {
                dce_alert(GID_DCE2, DCE2_SMB_MULTIPLE_NEGOTIATIONS,
                    (dce2CommonStats*)&dce2_smb_stats);
                return nullptr;
            }
            break;
        case SMB_COM_SESSION_SETUP_ANDX:
            break;
        case SMB_COM_TREE_CONNECT:
        case SMB_COM_TREE_CONNECT_ANDX:
        case SMB_COM_RENAME:
        case SMB_COM_LOGOFF_ANDX:
            if (DCE2_SmbFindUid(ssd, SmbUid(smb_hdr)) != DCE2_RET__SUCCESS)
                return nullptr;
            break;
        default:
            if (DCE2_SmbFindTid(ssd, SmbTid(smb_hdr)) != DCE2_RET__SUCCESS)
            {
                DebugFormat(DEBUG_DCE_SMB,
                    "Couldn't find Tid (%u)\n", SmbTid(smb_hdr));
                return nullptr;
            }

            if (DCE2_SmbIsTidIPC(ssd, SmbTid(smb_hdr)))
            {
                switch (smb_com)
                {
                case SMB_COM_OPEN:
                case SMB_COM_CREATE:
                case SMB_COM_CREATE_NEW:
                case SMB_COM_WRITE_AND_CLOSE:
                case SMB_COM_WRITE_AND_UNLOCK:
                case SMB_COM_READ:
                    // Samba doesn't allow these commands under an IPC tree
                    switch (policy)
                    {
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        DebugMessage(DEBUG_DCE_SMB, "Samba doesn't "
                            "process this command under an IPC tree.\n");
                        return nullptr;
                    default:
                        break;
                    }
                    break;
                case SMB_COM_READ_RAW:
                case SMB_COM_WRITE_RAW:
                    // Samba and Windows Vista on don't allow these commands
                    // under an IPC tree, whether or not the raw read/write
                    // flag is set in the Negotiate capabilities.
                    // Windows RSTs the connection and Samba FINs it.
                    switch (policy)
                    {
                    case DCE2_POLICY__WINVISTA:
                    case DCE2_POLICY__WIN2008:
                    case DCE2_POLICY__WIN7:
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        DebugMessage(DEBUG_DCE_SMB, "Samba and "
                            "Windows Vista on don't process this "
                            "command under an IPC tree.\n");
                        return nullptr;
                    default:
                        break;
                    }
                    break;
                case SMB_COM_LOCK_AND_READ:
                    // The lock will fail so the read won't happen
                    return nullptr;
                default:
                    break;
                }
            }
            else      // Not IPC
            {
                switch (smb_com)
                {
                // These commands are only used for IPC
                case SMB_COM_TRANSACTION:
                case SMB_COM_TRANSACTION_SECONDARY:
                    DebugMessage(DEBUG_DCE_SMB, "secondary transaction not IPC.\n");
                    return nullptr;
                case SMB_COM_READ_RAW:
                case SMB_COM_WRITE_RAW:
                    // Windows Vista on don't seem to support these
                    // commands, whether or not the raw read/write
                    // flag is set in the Negotiate capabilities.
                    // Windows RSTs the connection.
                    switch (policy)
                    {
                    case DCE2_POLICY__WINVISTA:
                    case DCE2_POLICY__WIN2008:
                    case DCE2_POLICY__WIN7:
                        DebugMessage(DEBUG_DCE_SMB,
                            "Windows Vista on don't process "
                            "this command.\n");
                        return nullptr;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }
            }
            break;
        }

        switch (smb_com)
        {
        case SMB_COM_TRANSACTION_SECONDARY:
        case SMB_COM_TRANSACTION2_SECONDARY:
        case SMB_COM_NT_TRANSACT_SECONDARY:
            rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
            break;
        case SMB_COM_TRANSACTION:
        case SMB_COM_TRANSACTION2:
        case SMB_COM_NT_TRANSACT:
            // If there is already and existing request tracker
            // and the transaction is not complete, server will
            // return an error.
            rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
            if (rtracker != nullptr)
                break;
        // Fall through
        default:
            rtracker = DCE2_SmbNewRequestTracker(ssd, smb_hdr);
            break;
        }
    }
    else
    {
        rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
    }

    return rtracker;
}

/********************************************************************
 * Function: DCE2_SmbCheckData()
 *
 * Purpose:
 *  Ensures that the data size reported in an SMB command is kosher.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count from the SMB command
 *  const uint16_t    - reported data count in SMB command
 *  const uint16_t    - reported data offset in SMB command
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbCheckData(DCE2_SmbSsnData*,
    const uint8_t* smb_hdr_ptr, const uint8_t* nb_ptr,
    const uint32_t nb_len, const uint16_t bcc,
    const uint32_t dcnt, uint16_t doff)
{
    const uint8_t* offset = smb_hdr_ptr + doff;
    const uint8_t* nb_end = nb_ptr + nb_len;

    // Byte counts don't usually matter, so no error but still alert
    // Don't alert in the case where the data count is larger than what the
    // byte count can handle.  This can happen if CAP_LARGE_READX or
    // CAP_LARGE_WRITEX were negotiated.
    if ((dcnt <= UINT16_MAX) && (bcc < dcnt))
        dce_alert(GID_DCE2, DCE2_SMB_BCC_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);

    if (offset > nb_end)
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
        // Error if offset is beyond data left
        return DCE2_RET__ERROR;
    }

    // Only check if the data count is non-zero
    if ((dcnt != 0) && (offset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    // Not necessarily an error if the addition of the data count goes
    // beyond the data left
    if (((offset + dcnt) > nb_end)           // beyond data left
        || ((offset + dcnt) < offset))       // wrap
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
    }

    return DCE2_RET__SUCCESS;
}

// Temporary command function placeholder, until all of them are ported
DCE2_Ret DCE2_SmbComFuncPlaceholder(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t)
{
    return DCE2_RET__SUCCESS;
}

static bool DCE2_SmbAutodetect(Packet* p)
{
    if (p->dsize > (sizeof(NbssHdr) + sizeof(SmbNtHdr)))
    {
        NbssHdr* nb_hdr = (NbssHdr*)p->data;
        SmbNtHdr* smb_hdr = (SmbNtHdr*)(p->data + sizeof(NbssHdr));

        if ((SmbId(smb_hdr) != DCE2_SMB_ID)
            && (SmbId(smb_hdr) != DCE2_SMB2_ID))
        {
            return false;
        }

        switch (NbssType(nb_hdr))
        {
        // FIXIT-L currently all ports are treated as autodetect.
        // On port 139, there is always an initial Session Request / Session Positive/Negative
        // response.
        // These message types were added , to make sure port 139 is treated as smb.
        // Remove once detect/autodetect supported.
        case NBSS_SESSION_TYPE__REQUEST:
            if (DCE2_SsnFromClient(p))
                return true;
            break;

        case NBSS_SESSION_TYPE__POS_RESPONSE:
        case NBSS_SESSION_TYPE__NEG_RESPONSE:
            if (DCE2_SsnFromServer(p))
                return true;
            break;

        case NBSS_SESSION_TYPE__MESSAGE:
            return true;
            break;
        default:
            break;
        }
    }

    return false;
}

void DCE2_SmbDataFree(DCE2_SmbSsnData* ssd)
{
    if (ssd == nullptr)
        return;

    // FIXIT This tries to account for the situation where we never knew the file
    // size and the TCP session was shutdown before an SMB_COM_CLOSE on the file.
    // Possibly need to add callback to fileAPI since it may have already
    // released it's resources.
    //DCE2_SmbFinishFileAPI(ssd);

    if (ssd->uids != nullptr)
    {
        DCE2_ListDestroy(ssd->uids);
        ssd->uids = nullptr;
    }

    if (ssd->tids != nullptr)
    {
        DCE2_ListDestroy(ssd->tids);
        ssd->tids = nullptr;
    }

    DCE2_SmbCleanFileTracker(&ssd->ftracker);
    if (ssd->ftrackers != nullptr)
    {
        DCE2_ListDestroy(ssd->ftrackers);
        ssd->ftrackers = nullptr;
    }

    DCE2_SmbCleanRequestTracker(&ssd->rtracker);
    if (ssd->rtrackers != nullptr)
    {
        DCE2_QueueDestroy(ssd->rtrackers);
        ssd->rtrackers = nullptr;
    }

    if (ssd->cli_seg != nullptr)
    {
        DCE2_BufferDestroy(ssd->cli_seg);
        ssd->cli_seg = nullptr;
    }

    if (ssd->srv_seg != nullptr)
    {
        DCE2_BufferDestroy(ssd->srv_seg);
        ssd->srv_seg = nullptr;
    }
}

Dce2SmbFlowData::Dce2SmbFlowData() : FlowData(flow_id)
{
}

Dce2SmbFlowData::~Dce2SmbFlowData()
{
    DCE2_SmbDataFree(&dce2_smb_session);
}

unsigned Dce2SmbFlowData::flow_id = 0;

DCE2_SmbSsnData* get_dce2_smb_session_data(Flow* flow)
{
    Dce2SmbFlowData* fd = (Dce2SmbFlowData*)flow->get_application_data(
        Dce2SmbFlowData::flow_id);

    return fd ? &fd->dce2_smb_session : nullptr;
}

static DCE2_SmbSsnData* set_new_dce2_smb_session(Packet* p)
{
    Dce2SmbFlowData* fd = new Dce2SmbFlowData;

    memset(&fd->dce2_smb_session,0,sizeof(DCE2_SmbSsnData));
    p->flow->set_application_data(fd);
    return(&fd->dce2_smb_session);
}

static DCE2_SmbSsnData* dce2_create_new_smb_session(Packet* p, dce2SmbProtoConf* config)
{
    DCE2_SmbSsnData* dce2_smb_sess = nullptr;
    Profile profile(dce2_smb_pstat_new_session);

    //FIXIT-M Re-evaluate after infrastructure/binder support if autodetect here
    //is necessary

    if (DCE2_SmbAutodetect(p))
    {
        DebugMessage(DEBUG_DCE_SMB, "DCE over SMB packet detected\n");
        DebugMessage(DEBUG_DCE_SMB, "Creating new session\n");

        dce2_smb_sess = set_new_dce2_smb_session(p);
        if ( dce2_smb_sess )
        {
            dce2_smb_sess->dialect_index = DCE2_SENTINEL;
            dce2_smb_sess->max_outstanding_requests = 10;  // Until Negotiate/SessionSetupAndX
            dce2_smb_sess->cli_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
            dce2_smb_sess->srv_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
            dce2_smb_sess->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;
            dce2_smb_sess->uid = DCE2_SENTINEL;
            dce2_smb_sess->tid = DCE2_SENTINEL;
            dce2_smb_sess->ftracker.fid = DCE2_SENTINEL;
            dce2_smb_sess->rtracker.mid = DCE2_SENTINEL;
            dce2_smb_sess->max_file_depth = FileService::get_max_file_depth();

            DCE2_ResetRopts(&dce2_smb_sess->sd.ropts);

            dce2_smb_stats.smb_sessions++;
            DebugFormat(DEBUG_DCE_SMB,"Created (%p)\n", (void*)dce2_smb_sess);

            dce2_smb_sess->sd.trans = DCE2_TRANS_TYPE__SMB;
            dce2_smb_sess->sd.server_policy = config->common.policy;
            dce2_smb_sess->sd.client_policy = DCE2_POLICY__WINXP;
            dce2_smb_sess->sd.wire_pkt = p;
            dce2_smb_sess->sd.config = (void*)config;

            DCE2_SsnSetAutodetected(&dce2_smb_sess->sd, p);
        }
    }

    return dce2_smb_sess;
}

static DCE2_SmbSsnData* dce2_handle_smb_session(Packet* p, dce2SmbProtoConf* config)
{
    Profile profile(dce2_smb_pstat_session);

    DCE2_SmbSsnData* dce2_smb_sess =  get_dce2_smb_session_data(p->flow);

    if (dce2_smb_sess == nullptr)
    {
        dce2_smb_sess = dce2_create_new_smb_session(p, config);
    }
    else
    {
        DCE2_SsnData* sd = (DCE2_SsnData*)dce2_smb_sess;
        sd->wire_pkt = p;

        if (DCE2_SsnAutodetected(sd) && !(p->packet_flags & sd->autodetect_dir))
        {
            /* Try to autodetect in opposite direction */
            if (!DCE2_SmbAutodetect(p))
            {
                DebugMessage(DEBUG_DCE_SMB, "Bad autodetect.\n");
                DCE2_SsnNoInspect(sd);
                dce2_smb_stats.sessions_aborted++;
                dce2_smb_stats.bad_autodetects++;
                return nullptr;
            }
            DCE2_SsnClearAutodetected(sd);
        }
    }
    DebugFormat(DEBUG_DCE_SMB, "Session pointer: %p\n", (void*)dce2_smb_sess);

    // FIXIT-M add remaining session handling logic

    return dce2_smb_sess;
}

/********************************************************************
 * Function: DCE2_NbssHdrChecks()
 *
 * Purpose:
 *  Does validation of the NetBIOS header.  SMB will only run over
 *  the Session Message type.  On port 139, there is always an
 *  initial Session Request / Session Positive/Negative response
 *  followed by the normal SMB conversation, i.e. Negotiate,
 *  SessionSetupAndX, etc.
 *  Side effects are potential alerts for anomolous behavior.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  const NbssHdr *   - pointer to the NetBIOS Session Service
 *                      header structure.  Size is already validated.
 *
 * Returns:
 *  DCE2_Ret  -  DCE2_RET__SUCCESS if all goes well and processing
 *               should continue.
 *               DCE2_RET__IGNORE if it's not something we need to
 *               look at.
 *               DCE2_RET__ERROR if an invalid NetBIOS Session
 *               Service type is found.
 *
 ********************************************************************/
static DCE2_Ret DCE2_NbssHdrChecks(DCE2_SmbSsnData* ssd, const NbssHdr* nb_hdr)
{
    Packet* p = ssd->sd.wire_pkt;

    DebugMessage(DEBUG_DCE_SMB, "NetBIOS Session Service type: ");

    switch (NbssType(nb_hdr))
    {
    case NBSS_SESSION_TYPE__MESSAGE:
        /* Only want to look at session messages */
        DebugMessage(DEBUG_DCE_SMB, "Session Message\n");

        if (!DCE2_SmbIsRawData(ssd))
        {
            uint32_t nb_len = NbssLen(nb_hdr);

            if (nb_len == 0)
                return DCE2_RET__IGNORE;

            if (nb_len < sizeof(SmbNtHdr))
            {
                DebugFormat(DEBUG_DCE_SMB, "NetBIOS SS len(%u) < SMB header len(%u).\n",
                    sizeof(SmbNtHdr), sizeof(NbssHdr) + nb_len);

                // FIXIT-M port segment check
                // Same for all cases below
                dce_alert(GID_DCE2, DCE2_SMB_NB_LT_SMBHDR, (dce2CommonStats*)&dce2_smb_stats);
                return DCE2_RET__IGNORE;
            }
        }

        return DCE2_RET__SUCCESS;

    case NBSS_SESSION_TYPE__REQUEST:
        DebugMessage(DEBUG_DCE_SMB, "Session Request\n");
        if (DCE2_SsnFromServer(p))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_NBSS_TYPE, (dce2CommonStats*)&dce2_smb_stats);
        }

        break;

    case NBSS_SESSION_TYPE__POS_RESPONSE:
    case NBSS_SESSION_TYPE__NEG_RESPONSE:
    case NBSS_SESSION_TYPE__RETARGET_RESPONSE:
        if (DCE2_SsnFromClient(p))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_NBSS_TYPE, (dce2CommonStats*)&dce2_smb_stats);
        }

        break;

    case NBSS_SESSION_TYPE__KEEP_ALIVE:
        DebugMessage(DEBUG_DCE_SMB, "Session Keep Alive\n");
        break;

    default:
        DebugFormat(DEBUG_DCE_SMB,
            "Invalid Session Service type: 0x%02X\n", NbssType(nb_hdr));
        dce_alert(GID_DCE2, DCE2_SMB_BAD_NBSS_TYPE, (dce2CommonStats*)&dce2_smb_stats);

        return DCE2_RET__ERROR;
    }

    return DCE2_RET__IGNORE;
}

/********************************************************************
 * Function: DCE2_SmbProcess()
 *
 * Purpose:
 *  This is the main entry point for SMB processing.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbProcess(DCE2_SmbSsnData* ssd)
{
    DebugMessage(DEBUG_DCE_SMB, "Processing SMB packet.\n");
    dce2_smb_stats.smb_pkts++;

    const Packet* p = ssd->sd.wire_pkt;
    const uint8_t* data_ptr = p->data;
    uint16_t data_len = p->dsize;

    /* Have to account for segmentation.  Even though stream will give
     * us larger chunks, we might end up in the middle of something */
    while (data_len > 0)
    {
        // We are ignoring an entire PDU or junk data so state should be NETBIOS_HEADER
        // Note that it could be TCP segmented so ignore_bytes could be greater than
        // the amount of data we have
        uint32_t* ignore_bytes = DCE2_SmbGetIgnorePtr(ssd);
        if (*ignore_bytes)
        {
            DebugFormat(DEBUG_DCE_SMB, "Ignoring %u bytes\n", *ignore_bytes);

            if (data_len <= *ignore_bytes)
            {
                *ignore_bytes -= data_len;
                return;
            }
            else
            {
                /* ignore bytes is less than UINT16_MAX */
                DCE2_MOVE(data_ptr, data_len, (uint16_t)*ignore_bytes);
                *ignore_bytes = 0;
            }
        }

        DCE2_SmbDataState* data_state = DCE2_SmbGetDataState(ssd);
        DCE2_SmbRequestTracker* rtracker = nullptr;
        switch (*data_state)
        {
        // This state is to verify it's a NetBIOS Session Message packet
        // and to get the length of the SMB PDU.  Also does the SMB junk
        // data check.  If it's not a Session Message the data isn't
        // processed since it won't be carrying SMB.
        case DCE2_SMB_DATA_STATE__NETBIOS_HEADER:
        {
            uint32_t data_need = sizeof(NbssHdr);

            // See if there is enough data to process the NetBIOS header
            if (data_len < data_need)
            {
                DebugFormat(DEBUG_DCE_SMB, "Data len(%u) < NetBIOS SS header(%u). "
                    "Queueing data.\n", data_len, data_need);

                // FIXIT-M port segmentation code
                return;
            }

            // Set the NetBIOS header structure
            NbssHdr* nb_hdr = (NbssHdr*)data_ptr;
            uint32_t nb_len = NbssLen(nb_hdr);

            DebugFormat(DEBUG_DCE_SMB, "NetBIOS PDU length: %u\n", nb_len);

            DCE2_Ret status = DCE2_NbssHdrChecks(ssd, nb_hdr);
            if (status != DCE2_RET__SUCCESS)
            {
                DebugMessage(DEBUG_DCE_SMB, "Not a NetBIOS Session Message.\n");

                if (status == DCE2_RET__IGNORE)
                {
                    DebugMessage(DEBUG_DCE_SMB, "Valid NetBIOS header "
                        "type so ignoring NetBIOS length bytes.\n");
                    *ignore_bytes = data_need + nb_len;
                }
                else      // nb_ret == DCE2_RET__ERROR, i.e. invalid NetBIOS type
                {
                    DebugMessage(DEBUG_DCE_SMB, "Not a valid NetBIOS "
                        "header type so trying to find \\xffSMB to "
                        "determine how many bytes to ignore.\n");
                    *ignore_bytes = DCE2_IgnoreJunkData(data_ptr, data_len, data_need + nb_len);
                }

                dce2_smb_stats.smb_ignored_bytes += *ignore_bytes;
                continue;
            }

            switch (ssd->pdu_state)
            {
            case DCE2_SMB_PDU_STATE__COMMAND:
                *data_state = DCE2_SMB_DATA_STATE__SMB_HEADER;
                break;
            case DCE2_SMB_PDU_STATE__RAW_DATA:
                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_PDU;
                // Continue here because of fall through below
                continue;
            default:
                DebugFormat(DEBUG_DCE_SMB,"%s(%d) Invalid SMB PDU "
                    "state: %d\n", __FILE__, __LINE__, ssd->pdu_state);
                return;
            }
        }

        // Fall through for DCE2_SMB_DATA_STATE__SMB_HEADER
        // This is the normal progression without segmentation.

        // This state is to do validation checks on the SMB header and
        // more importantly verify it's data that needs to be inspected.
        // If the TID in the SMB header is not referring to the IPC share
        // there won't be any DCE/RPC traffic associated with it.
        case DCE2_SMB_DATA_STATE__SMB_HEADER:
        {
            // FIXIT-M add segmentation code path, including seg_buf code to the entire state

            uint32_t data_need = (sizeof(NbssHdr) + sizeof(SmbNtHdr));
            // See if there is enough data to process the SMB header
            if (data_len < data_need)
            {
                DebugFormat(DEBUG_DCE_SMB, "Data len (%u) < "
                    "NetBIOS SS header + SMB header (%u). Queueing data.\n",
                    data_len, data_need);

                // FIXIT-M add segmentation code path
                return;
            }

            // FIXIT-M add segmentation checks
            SmbNtHdr* smb_hdr = (SmbNtHdr*)(data_ptr + sizeof(NbssHdr));

            // FIXIT-L Don't support SMB2 yet
            if (SmbId(smb_hdr) == DCE2_SMB2_ID)
            {
                ssd->sd.flags |= DCE2_SSN_FLAG__NO_INSPECT;
                return;
            }

            // See if this is something we need to inspect
            rtracker = DCE2_SmbInspect(ssd, smb_hdr);
            if (rtracker == nullptr)
            {
                DebugMessage(DEBUG_DCE_SMB, "Not inspecting SMB packet.\n");

                // FIXIT-M add segmentation
                *ignore_bytes = sizeof(NbssHdr) + NbssLen((NbssHdr*)data_ptr);

                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                dce2_smb_stats.smb_ignored_bytes += *ignore_bytes;
                continue;
            }

            // Check the SMB header for anomolies
            if (DCE2_SmbHdrChecks(ssd, smb_hdr) != DCE2_RET__SUCCESS)
            {
                DebugMessage(DEBUG_DCE_SMB, "Bad SMB header.\n");

                *ignore_bytes = sizeof(NbssHdr) + NbssLen((NbssHdr*)data_ptr);

                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;

                dce2_smb_stats.smb_ignored_bytes += *ignore_bytes;
                continue;
            }

            *data_state = DCE2_SMB_DATA_STATE__NETBIOS_PDU;
        }

        // Fall through

        // This state ensures that we have the entire PDU before continuing
        // to process.
        case DCE2_SMB_DATA_STATE__NETBIOS_PDU:
        {
            uint32_t nb_len = NbssLen((NbssHdr*)data_ptr);
            uint32_t data_need = sizeof(NbssHdr) + nb_len;

            /* It's something we want to inspect so make sure we have the full NBSS packet */
            if (data_len < data_need)
            {
                DebugFormat(DEBUG_DCE_SMB, "Data len(%u) < "
                    "NetBIOS SS header + NetBIOS len(%u). "
                    "Queueing data.\n", data_len, sizeof(NbssHdr) + nb_len);

                // FIXIT-M add segmentation code

                return;
            }

            // data_len >= data_need which means data_need <= UINT16_MAX
            // So casts below of data_need to uint16_t are okay.

            *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;

            const uint8_t* nb_ptr = data_ptr;
            nb_len = data_need;
            DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);

            switch (ssd->pdu_state)
            {
            case DCE2_SMB_PDU_STATE__COMMAND:
            {
                SmbNtHdr* smb_hdr = (SmbNtHdr*)(nb_ptr + sizeof(NbssHdr));
                DCE2_MOVE(nb_ptr, nb_len, (sizeof(NbssHdr) + sizeof(SmbNtHdr)));
                ssd->cur_rtracker = (rtracker != nullptr)
                    ? rtracker : DCE2_SmbFindRequestTracker(ssd, smb_hdr);
                if (ssd->cur_rtracker != nullptr)
                    DCE2_SmbProcessCommand(ssd, smb_hdr, nb_ptr, nb_len);
                break;
            }

            case DCE2_SMB_PDU_STATE__RAW_DATA:
                //FIXIT-M port raw state
                break;
            default:
                DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid SMB PDU "
                    "state: %d\n", __FILE__, __LINE__, ssd->pdu_state);
                return;
            }
            break;
        }

        default:
            DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid SMB Data "
                "state: %d\n", __FILE__, __LINE__, *data_state);
            return;
        }
    }
}

/********************************************************************
 * Function: DCE2_SmbInitGlobals()
 *
 * Purpose:
 *  Initializes global variables for SMB processing.
 *  Sets up the functions and valid word and byte counts for SMB
 *  commands.
 *  Sets up AndX chain mappings and valid command chaining for
 *  supported policies.
 *
 * Arguments: None
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbInitGlobals()
{
    memset(&smb_wcts, 0, sizeof(smb_wcts));
    memset(&smb_bccs, 0, sizeof(smb_bccs));

    // Sets up the function to call for the command and valid word and byte
    // counts for the command.  Ensuring valid word and byte counts is very
    // important to processing the command as it will assume the command is
    // legitimate and can access data that is acutally there.  Note that
    // commands with multiple word counts indicate a different command
    // structure, however most, if not all just have an extended version
    // of the structure for which the extended part isn't used.  If the
    // extended part of a command structure needs to be used, be sure to
    // check the word count in the command function before accessing data
    // in the extended version of the command structure.
    for (int com = 0; com < SMB_MAX_NUM_COMS; com++)
    {
        switch (com)
        {
        case SMB_COM_OPEN:
            // FIXIT-M port DCE2_SmbOpen. Same for other smb_com_funcs
            smb_com_funcs[com] = DCE2_SmbOpen;

            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 2);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 7);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_CREATE:
            smb_com_funcs[com] = DCE2_SmbCreate;

            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_CLOSE:
            smb_com_funcs[com] = DCE2_SmbClose;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_RENAME:
            smb_com_funcs[com] = DCE2_SmbRename;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 1);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 4, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_READ:
            smb_com_funcs[com] = DCE2_SmbRead;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 5);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 3, UINT16_MAX);
            break;
        case SMB_COM_WRITE:
            smb_com_funcs[com] = DCE2_SmbWrite;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_CREATE_NEW:
            smb_com_funcs[com] = DCE2_SmbCreateNew;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_LOCK_AND_READ:
            smb_com_funcs[com] = DCE2_SmbLockAndRead;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 5);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 3, UINT16_MAX);
            break;
        case SMB_COM_WRITE_AND_UNLOCK:
            smb_com_funcs[com] = DCE2_SmbWriteAndUnlock;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_READ_RAW:
            //smb_com_funcs[com] = DCE2_SmbReadRaw;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 8);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            // Response is raw data, i.e. without SMB
            break;
        case SMB_COM_WRITE_RAW:
            //smb_com_funcs[com] = DCE2_SmbWriteRaw;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);
            // Interim server response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_WRITE_COMPLETE:
            // Final server response to SMB_COM_WRITE_RAW
            //smb_com_funcs[com] = DCE2_SmbWriteComplete;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TRANSACTION:
            smb_com_funcs[com] = DCE2_SmbTransaction;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            // Word count depends on setup count
            //for (i = 14; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__REQUEST, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION requests
            // have a setup count of 2 words.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 16);

            // \PIPE\LANMAN
            // Not something the preprocessor is looking at as it
            // doesn't carry DCE/RPC but don't want to false positive
            // on the preprocessor event.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);

            // Word count depends on setup count
            //for (i = 10; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__RESPONSE, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION responses
            // have a setup count of 0 words.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 10);

            // Interim server response
            // When client sends an incomplete transaction and needs to
            // send TransactionSecondary requests to complete request.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            // Exception will be made for Interim responses when
            // byte count is checked.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_TRANSACTION_SECONDARY:
            //smb_com_funcs[com] = DCE2_SmbTransactionSecondary;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 8);
            // Response is an SMB_COM_TRANSACTION

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            break;
        case SMB_COM_WRITE_AND_CLOSE:
            //smb_com_funcs[com] = DCE2_SmbWriteAndClose;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 6);
            // For some reason MS-CIFS specifies a version of this command
            // with 6 extra words (12 bytes) of reserved, i.e. useless data.
            // Maybe had intentions of extending and defining the data at
            // some point, but there is no documentation that I could find
            // that does.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 1, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_OPEN_ANDX:
            smb_com_funcs[com] = DCE2_SmbOpenAndX;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 15);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 15);
            // Extended response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 19);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            // MS-SMB says that Windows 2000, XP and Vista set this to
            // some arbitrary value that is ignored on receipt.
            //DCE2_SmbSetValidByteCount(com, SMB_TYPE__RESPONSE, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_READ_ANDX:
            smb_com_funcs[com] = DCE2_SmbReadAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 12);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_WRITE_ANDX:
            smb_com_funcs[com] = DCE2_SmbWriteAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 6);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 1, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TRANSACTION2:
            //smb_com_funcs[com] = DCE2_SmbTransaction2;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            // Word count depends on setup count
            //for (i = 14; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__REQUEST, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION2
            // requests have a setup count of 1 word.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 15);

            // Word count depends on setup count
            //for (i = 10; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__RESPONSE, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION2
            // responses have a setup count of 0 or 1 word.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 10);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 11);

            // Interim server response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            // Exception will be made for Interim responses when
            // byte count is checked.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_TRANSACTION2_SECONDARY:
            //smb_com_funcs[com] = DCE2_SmbTransaction2Secondary;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 9);
            // Response is an SMB_COM_TRANSACTION2

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            break;
        case SMB_COM_TREE_CONNECT:
            smb_com_funcs[com] = DCE2_SmbTreeConnect;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 6, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TREE_DISCONNECT:
            smb_com_funcs[com] = DCE2_SmbTreeDisconnect;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_NEGOTIATE:
            smb_com_funcs[com] = DCE2_SmbNegotiate;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 13);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 17);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            // This can vary depending on dialect so just set wide.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_SESSION_SETUP_ANDX:
            smb_com_funcs[com] = DCE2_SmbSessionSetupAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 13);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 4);

            // These can vary so just set wide.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_LOGOFF_ANDX:
            smb_com_funcs[com] = DCE2_SmbLogoffAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 2);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);
            // Windows responds to a LogoffAndX => SessionSetupAndX with just a
            // LogoffAndX and with the word count field containing 3, but only
            // has 2 words
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TREE_CONNECT_ANDX:
            smb_com_funcs[com] = DCE2_SmbTreeConnectAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 4);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);
            // Extended response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 7);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 2, UINT16_MAX);
            break;
        case SMB_COM_NT_TRANSACT:
            //smb_com_funcs[com] = DCE2_SmbNtTransact;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            // Word count depends on setup count
            // In reality, all subcommands of SMB_COM_NT_TRANSACT
            // requests have a setup count of 0 or 4 words.
            //for (i = 19; i < 256; i++)
            //    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, i);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 19);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 23);

            // Word count depends on setup count
            // In reality, all subcommands of SMB_COM_NT_TRANSACT
            // responses have a setup count of 0 or 1 word.
            //for (i = 18; i < 256; i++)
            //    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, i);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 18);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 19);

            // Interim server response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            // Exception will be made for Interim responses when
            // byte count is checked.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_NT_TRANSACT_SECONDARY:
            //smb_com_funcs[com] = DCE2_SmbNtTransactSecondary;
            smb_com_funcs[com] = DCE2_SmbComFuncPlaceholder;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 18);
            // Response is an SMB_COM_NT_TRANSACT

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            break;
        case SMB_COM_NT_CREATE_ANDX:
            smb_com_funcs[com] = DCE2_SmbNtCreateAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 24);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 34);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 26);
            // Extended response - though there are actually 50 words
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 42);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            // MS-SMB indicates that this field should be 0 but may be
            // sent uninitialized so basically ignore it.
            //DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        default:
            smb_com_funcs[com] = nullptr;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;
            // Just set to all valid since the specific command won't
            // be processed.  Don't want to false positive on these.
            for (int i = 0; i < 256; i++)
            {
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, (uint8_t)i);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, (uint8_t)i);
            }
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        }
    }

    // Maps commands for use in quickly determining if a command
    // is chainable and what command it is.
    for (int com = 0; com < SMB_MAX_NUM_COMS; com++)
    {
        switch (com)
        {
        case SMB_COM_SESSION_SETUP_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__SESSION_SETUP_ANDX;
            break;
        case SMB_COM_LOGOFF_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__LOGOFF_ANDX;
            break;
        case SMB_COM_TREE_CONNECT_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__TREE_CONNECT_ANDX;
            break;
        case SMB_COM_OPEN_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__OPEN_ANDX;
            break;
        case SMB_COM_NT_CREATE_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__NT_CREATE_ANDX;
            break;
        case SMB_COM_WRITE_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__WRITE_ANDX;
            break;
        case SMB_COM_READ_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__READ_ANDX;
            break;
        default:
            smb_chain_map[com] = SMB_ANDX_COM__NONE;
            break;
        }
    }

    // Sets up the valid command chaining combinations per policy
    for (int policy = 0; policy < DCE2_POLICY__MAX; policy++)
    {
        for (int andx = SMB_ANDX_COM__NONE; andx < SMB_ANDX_COM__MAX; andx++)
        {
            /* com is the chained command or com2 */
            for (int com = 0; com < SMB_MAX_NUM_COMS; com++)
            {
                DCE2_SmbComFunc com_func = nullptr;

                switch (policy)
                {
                case DCE2_POLICY__WIN2000:
                case DCE2_POLICY__WINXP:
                case DCE2_POLICY__WINVISTA:
                case DCE2_POLICY__WIN2003:
                case DCE2_POLICY__WIN2008:
                case DCE2_POLICY__WIN7:
                    switch (andx)
                    {
                    case SMB_ANDX_COM__SESSION_SETUP_ANDX:
                        switch (com)
                        {
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_OPEN:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_CREATE:
                        case SMB_COM_CREATE_NEW:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_TRANSACTION:
                            if (policy == DCE2_POLICY__WIN2000)
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__LOGOFF_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_TREE_CONNECT_ANDX:               // Only for responses
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__TREE_CONNECT_ANDX:
                        switch (com)
                        {
                        case SMB_COM_OPEN:
                        case SMB_COM_CREATE:
                        case SMB_COM_CREATE_NEW:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_TRANSACTION:
                            if (policy == DCE2_POLICY__WIN2000)
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__OPEN_ANDX:
                        break;
                    case SMB_ANDX_COM__NT_CREATE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_READ_ANDX:              // Only for normal files
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__WRITE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE_ANDX:
                        case SMB_COM_READ:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__READ_ANDX:
                        break;
                    default:
                        break;
                    }
                    break;
                case DCE2_POLICY__SAMBA:
                case DCE2_POLICY__SAMBA_3_0_37:
                case DCE2_POLICY__SAMBA_3_0_22:
                case DCE2_POLICY__SAMBA_3_0_20:
                    switch (andx)
                    {
                    case SMB_ANDX_COM__SESSION_SETUP_ANDX:
                        switch (com)
                        {
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_WRITE:
                            if ((policy == DCE2_POLICY__SAMBA_3_0_22)
                                || (policy == DCE2_POLICY__SAMBA_3_0_20))
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__LOGOFF_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__TREE_CONNECT_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__OPEN_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__NT_CREATE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_CLOSE:
                            if ((policy == DCE2_POLICY__SAMBA)
                                || (policy == DCE2_POLICY__SAMBA_3_0_37))
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__WRITE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                        case SMB_COM_WRITE_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__READ_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_WRITE:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_READ_ANDX:
                            if ((policy == DCE2_POLICY__SAMBA)
                                || (policy == DCE2_POLICY__SAMBA_3_0_37))
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }

                smb_chain_funcs[policy][andx][com] = com_func;
            }
        }
    }
}

// Convenience function to determine whether or not the transaction is complete
// for one side, i.e. all data and parameters sent.
static inline bool DCE2_SmbIsTransactionComplete(DCE2_SmbTransactionTracker* ttracker)
{
    if ((ttracker->tdcnt == ttracker->dsent)
        && (ttracker->tpcnt == ttracker->psent))
        return true;
    return false;
}

/********************************************************************
 * Function: DCE2_SmbCheckAndXOffset()
 *
 * Purpose:
 *  Validates that the AndXOffset is within bounds of the remaining
 *  data we have to work with.
 *
 * Arguments:
 *  uint8_t * - pointer to where the offset would take us.
 *  uint8_t * - pointer to bound offset
 *  uint8_t * - length of data where offset should be within
 *
 * Returns:
 *  DCE2_RET__SUCCESS - Offset is okay.
 *  DCE2_RET__ERROR   - Offset is bad.
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbCheckAndXOffset(const uint8_t* off_ptr, const uint8_t* start_bound,
    const uint32_t length)
{
    /* Offset should not point within data we just looked at or be equal to
     * or beyond the length of the NBSS length left */
    if ((off_ptr < start_bound) ||
        (off_ptr > (start_bound + length)))
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);

        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

static void DCE2_SmbQueueTmpFileTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbRequestTracker* rtracker, const uint16_t uid, const uint16_t tid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB, "Queueing file tracker "
        "with Uid: %u, Tid: %u\n", uid, tid);

    DCE2_SmbFileTracker* ftracker = (DCE2_SmbFileTracker*)
        snort_calloc(sizeof(DCE2_SmbFileTracker));

    if (ftracker == nullptr)
    {
        return;
    }

    bool is_ipc = DCE2_SmbIsTidIPC(ssd, tid);
    if (DCE2_SmbInitFileTracker(ssd, ftracker, is_ipc, uid, tid, DCE2_SENTINEL) !=
        DCE2_RET__SUCCESS)
    {
        DCE2_SmbCleanFileTracker(ftracker);
        snort_free((void*)ftracker);
        return;
    }

    if (!is_ipc && (ssd->fapi_ftracker == ftracker))
        ssd->fapi_ftracker = nullptr;

    if (rtracker->ft_queue == nullptr)
    {
        rtracker->ft_queue = DCE2_QueueNew(DCE2_SmbFileTrackerDataFree);
        if (rtracker->ft_queue == nullptr)
        {
            DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
            return;
        }
    }

    if (DCE2_QueueEnqueue(rtracker->ft_queue, (void*)ftracker) != DCE2_RET__SUCCESS)
    {
        DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
        return;
    }
}

/********************************************************************
 * Function: DCE2_SmbInvalidShareCheck()
 *
 * Purpose:
 *  Checks the share reported in a TreeConnect or TreeConnectAndX
 *  against the invalid share list configured in the dcerpc2
 *  configuration in snort.conf.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t *         - current pointer to the share to check
 *  uint32_t          - the remaining length
 *
 * Returns: None
 *  Alerts if there is an invalid share match.
 *
 ********************************************************************/
static void DCE2_SmbInvalidShareCheck(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DCE2_List* share_list = DCE2_ScSmbInvalidShares((dce2SmbProtoConf*)ssd->sd.config);
    if (share_list == nullptr)
        return;

    dce2SmbShare* smb_share;
    for (smb_share = (dce2SmbShare*)DCE2_ListFirst(share_list);
        smb_share != nullptr;
        smb_share = (dce2SmbShare*)DCE2_ListNext(share_list))
    {
        unsigned int i;
        const char* share_str;
        unsigned int share_str_len;

        if (SmbUnicode(smb_hdr))
        {
            share_str = smb_share->unicode_str;
            share_str_len = smb_share->unicode_str_len;
        }
        else
        {
            share_str = smb_share->ascii_str;
            share_str_len = smb_share->ascii_str_len;
        }

        /* Make sure we have enough data */
        if (nb_len < share_str_len)
            continue;

        /* Test for share match */
        for (i = 0; i < share_str_len; i++)
        {
            /* All share strings should have been converted to upper case and
             * should include null terminating bytes */
            if ((nb_ptr[i] != share_str[i]) && (nb_ptr[i] != tolower((int)share_str[i])))
                break;
        }

        if (i == share_str_len)
        {
            /* Should only match one share since no duplicate shares in list */
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_SHARE, (dce2CommonStats*)&dce2_smb_stats);
            break;
        }
    }
}

/********************************************************************
 * Functions:
 *   DCE2_SmbOpen()
 *   DCE2_SmbCreate()
 *   DCE2_SmbClose()
 *   DCE2_SmbRename()
 *   DCE2_SmbRead()
 *   DCE2_SmbWrite()
 *   DCE2_SmbCreateNew()
 *   DCE2_SmbLockAndRead()
 *   DCE2_SmbWriteAndUnlock()
 *   DCE2_SmbReadRaw()
 *   DCE2_SmbWriteRaw()
 *   DCE2_SmbWriteComplete()
 *   DCE2_SmbTransaction()
 *   DCE2_SmbTransactionSecondary()
 *   DCE2_SmbWriteAndClose()
 *   DCE2_SmbOpenAndX()
 *   DCE2_SmbReadAndX()
 *   DCE2_SmbWriteAndX()
 *   DCE2_SmbTransaction2()
 *   DCE2_SmbTransaction2Secondary()
 *   DCE2_SmbTreeConnect()
 *   DCE2_SmbTreeDisconnect()
 *   DCE2_SmbNegotiate()
 *   DCE2_SmbSessionSetupAndX()
 *   DCE2_SmbLogoffAndX()
 *   DCE2_SmbTreeConnectAndX()
 *   DCE2_SmbNtTransact()
 *   DCE2_SmbNtTransactSecondary()
 *   DCE2_SmbNtCreateAndX()
 *
 * Purpose: Process SMB command
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - SMB session data structure
 *  const SmbNtHdr *        - SMB header structure (packet pointer)
 *  const DCE2_SmbComInfo * - Basic command information structure
 *  uint8_t *               - pointer to start of command (packet pointer)
 *  uint32_t                - remaining NetBIOS length
 *
 * Returns:
 *  DCE2_Ret - DCE2_RET__ERROR if something went wrong and/or processing
 *               should stop
 *             DCE2_RET__SUCCESS if processing should continue
 *
 ********************************************************************/

// SMB_COM_OPEN
static DCE2_Ret DCE2_SmbOpen(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbFileTracker* ftracker;

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid)
            && (SmbFileAttrsDirectory(SmbOpenRespFileAttrs((SmbOpenResp*)nb_ptr))
            || SmbOpenForWriting(SmbOpenRespAccessMode((SmbOpenResp*)nb_ptr))))
            return DCE2_RET__SUCCESS;

        ftracker = DCE2_SmbNewFileTracker(ssd, ssd->cur_rtracker->uid,
            ssd->cur_rtracker->tid, SmbOpenRespFid((SmbOpenResp*)nb_ptr));
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        if (!ftracker->is_ipc)
        {
            // This command can only be used to open an existing file
            ftracker->ff_file_size = SmbOpenRespFileSize((SmbOpenResp*)nb_ptr);
        }
    }
    else
    {
        // Have at least 2 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        ssd->cur_rtracker->file_name =
            DCE2_SmbGetString(nb_ptr, nb_len, SmbUnicode(smb_hdr), false);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CREATE
static DCE2_Ret DCE2_SmbCreate(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbFileTracker* ftracker = DCE2_SmbNewFileTracker(
            ssd, ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
            SmbCreateRespFid((SmbCreateResp*)nb_ptr));

        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        // Command creates or opens and truncates file to 0 so assume
        // upload.
        if (!ftracker->is_ipc)
            ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
    }
    else
    {
        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbCreateReqFileAttrs((SmbCreateReq*)nb_ptr);

            if (SmbAttrDirectory(file_attrs))
                return DCE2_RET__IGNORE;

            if (SmbEvasiveFileAttrs(file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
        }

        // Have at least 2 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        ssd->cur_rtracker->file_name =
            DCE2_SmbGetString(nb_ptr, nb_len, SmbUnicode(smb_hdr), false);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CLOSE
static DCE2_Ret DCE2_SmbClose(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t fid = SmbCloseReqFid((SmbCloseReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = DCE2_SmbGetFileTracker(ssd, fid);

        //FIXIT-M port active response related code
/*
#ifdef ACTIVE_RESPONSE
        if ((ssd->fb_ftracker != NULL) && (ssd->fb_ftracker == ssd->cur_rtracker->ftracker))
        {
            void *ssnptr = ssd->sd.wire_pkt->stream_session;
            void *p = (void *)ssd->sd.wire_pkt;
            File_Verdict verdict = DCE2_SmbGetFileVerdict(p, ssnptr);

            if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT))
                ssd->block_pdus = true;
        }
#endif
*/
    }
    else
    {
        DCE2_SmbRemoveFileTracker(ssd, ssd->cur_rtracker->ftracker);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_RENAME
static DCE2_Ret DCE2_SmbRename(DCE2_SmbSsnData*, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    // NOTE: This command is only processed for CVE-2006-4696 where the buffer
    // formats are invalid and has no bearing on DCE/RPC processing.

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 4 bytes of data based on byte count check done earlier

        uint32_t i;

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        if (SmbUnicode(smb_hdr))
        {
            for (i = 0; i < (nb_len - 1); i += 2)
            {
                if (*((uint16_t*)(nb_ptr + i)) == 0)
                {
                    i += 2;  // move past null terminating bytes
                    break;
                }
            }
        }
        else
        {
            for (i = 0; i < nb_len; i++)
            {
                if (nb_ptr[i] == 0)
                {
                    i++;  // move past null terminating byte
                    break;
                }
            }
        }

        // i <= nb_len
        DCE2_MOVE(nb_ptr, nb_len, i);

        if ((nb_len > 0) && !SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }
    }

    // Don't care about tracking response
    return DCE2_RET__ERROR;
}

// SMB_COM_READ
static DCE2_Ret DCE2_SmbRead(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbGetFileTracker(ssd, SmbReadReqFid((SmbReadReq*)nb_ptr));

        // Set this for response since response doesn't have the Fid
        ssd->cur_rtracker->ftracker = ftracker;
        if ((ftracker != nullptr) && !ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbReadReqOffset((SmbReadReq*)nb_ptr);
    }
    else
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t com_dcnt = SmbReadRespCount((SmbReadResp*)nb_ptr);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt > nb_len)
            return DCE2_RET__ERROR;

        return DCE2_SmbProcessResponseData(ssd, nb_ptr, com_dcnt);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE
static DCE2_Ret DCE2_SmbWrite(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbWriteReqCount((SmbWriteReq*)nb_ptr);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteReqFid((SmbWriteReq*)nb_ptr);
        uint32_t offset = SmbWriteReqOffset((SmbWriteReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt == 0)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, com_dcnt, offset);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CREATE_NEW
static DCE2_Ret DCE2_SmbCreateNew(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbFileTracker* ftracker = DCE2_SmbNewFileTracker(
            ssd, ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
            SmbCreateNewRespFid((SmbCreateNewResp*)nb_ptr));

        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        // Command creates a new file so assume upload.
        if (!ftracker->is_ipc)
            ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
    }
    else
    {
        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbCreateNewReqFileAttrs((SmbCreateNewReq*)nb_ptr);

            if (SmbAttrDirectory(file_attrs))
                return DCE2_RET__IGNORE;

            if (SmbEvasiveFileAttrs(file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
        }

        // Have at least 2 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        ssd->cur_rtracker->file_name =
            DCE2_SmbGetString(nb_ptr, nb_len, SmbUnicode(smb_hdr), false);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_LOCK_AND_READ
static DCE2_Ret DCE2_SmbLockAndRead(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbFindFileTracker(ssd, ssd->cur_rtracker->uid,
            ssd->cur_rtracker->tid, SmbLockAndReadReqFid((SmbLockAndReadReq*)nb_ptr));

        // No sense in tracking response
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        if (!ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbLockAndReadReqOffset((SmbLockAndReadReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbLockAndReadRespCount((SmbLockAndReadResp*)nb_ptr);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        DebugFormat(DEBUG_DCE_SMB," SmbWriteLockAndRead dcnt %d\n", com_dcnt);
        if (com_dcnt == 0)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        return DCE2_SmbProcessResponseData(ssd, nb_ptr, com_dcnt);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_AND_UNLOCK
static DCE2_Ret DCE2_SmbWriteAndUnlock(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
    {
        if (DCE2_ComInfoIsBadLength(com_info) || DCE2_ComInfoIsInvalidWordCount(com_info))
            return DCE2_RET__ERROR;

        // These are special cases.  The write succeeds but the unlock fails
        // so an error reponse is returned but the data was actually written.
        if (DCE2_ComInfoIsResponse(com_info) && DCE2_ComInfoIsStatusError(com_info))
        {
            if (DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
            {
                if (!SmbErrorInvalidDeviceRequest(smb_hdr))
                    return DCE2_RET__ERROR;
            }
            else if (!SmbErrorRangeNotLocked(smb_hdr))
            {
                return DCE2_RET__ERROR;
            }
        }
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbWriteAndUnlockReqCount((SmbWriteAndUnlockReq*)nb_ptr);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteAndUnlockReqFid((SmbWriteAndUnlockReq*)nb_ptr);
        uint32_t offset = SmbWriteAndUnlockReqOffset((SmbWriteAndUnlockReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt == 0)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, com_dcnt, offset);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_OPEN_ANDX
static DCE2_Ret DCE2_SmbOpenAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        const uint16_t fid = SmbOpenAndXRespFid((SmbOpenAndXResp*)nb_ptr);
        const uint16_t file_attrs = SmbOpenAndXRespFileAttrs((SmbOpenAndXResp*)nb_ptr);
        const uint16_t resource_type = SmbOpenAndXRespResourceType((SmbOpenAndXResp*)nb_ptr);
        DCE2_SmbFileTracker* ftracker = nullptr;

        // Set request tracker's current file tracker in case of chained commands
        switch (SmbAndXCom2((SmbAndXCommon*)nb_ptr))
        {
        // This is in case in the request a write was chained to an open
        // in which case the write will be to the newly opened file
        case SMB_COM_WRITE:
        case SMB_COM_WRITE_ANDX:
        case SMB_COM_TRANSACTION:
        case SMB_COM_READ_ANDX:
            ftracker = DCE2_SmbDequeueTmpFileTracker(ssd, ssd->cur_rtracker, fid);
            break;
        default:
            break;
        }

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid)
            && (SmbFileAttrsDirectory(file_attrs)
            || !SmbResourceTypeDisk(resource_type)))
        {
            if (ftracker != nullptr)
                DCE2_SmbRemoveFileTracker(ssd, ftracker);
            return DCE2_RET__SUCCESS;
        }

        if (ftracker == nullptr)
        {
            ftracker = DCE2_SmbNewFileTracker(ssd,
                ssd->cur_rtracker->uid, ssd->cur_rtracker->tid, fid);
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;
        }

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        if (!ftracker->is_ipc)
        {
            const uint16_t open_results = SmbOpenAndXRespOpenResults((SmbOpenAndXResp*)nb_ptr);

            if (SmbOpenResultRead(open_results))
            {
                ftracker->ff_file_size = SmbOpenAndXRespFileSize((SmbOpenAndXResp*)nb_ptr);
            }
            else
            {
                ftracker->ff_file_size = ssd->cur_rtracker->file_size;
                ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
            }
        }

        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        uint32_t pad = 0;
        const bool unicode = SmbUnicode(smb_hdr);
        uint8_t null_bytes = unicode ? 2 : 1;

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbOpenAndXReqFileAttrs((SmbOpenAndXReq*)nb_ptr);

            if (SmbEvasiveFileAttrs(file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
            ssd->cur_rtracker->file_size = SmbOpenAndXReqAllocSize((SmbOpenAndXReq*)nb_ptr);
        }

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (unicode)
            pad = (nb_ptr - (const uint8_t*)smb_hdr) & 1;

        if (nb_len < (pad + null_bytes))
            return DCE2_RET__ERROR;

        DCE2_MOVE(nb_ptr, nb_len, pad);

        // Samba allows chaining OpenAndX/NtCreateAndX so might have
        // already been set.
        if (ssd->cur_rtracker->file_name == nullptr)
        {
            ssd->cur_rtracker->file_name =
                DCE2_SmbGetString(nb_ptr, nb_len, unicode, false);
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_READ_ANDX
static DCE2_Ret DCE2_SmbReadAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbGetFileTracker(ssd, SmbReadAndXReqFid((SmbReadAndXReq*)nb_ptr));

        // No sense in tracking response
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        if (!ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbReadAndXReqOffset((SmbReadAndXExtReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t doff = SmbReadAndXRespDataOff((SmbReadAndXResp*)nb_ptr);
        uint32_t dcnt = SmbReadAndXRespDataCnt((SmbReadAndXResp*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
            dcnt = nb_len;

        return DCE2_SmbProcessResponseData(ssd, nb_ptr, dcnt);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_ANDX
static DCE2_Ret DCE2_SmbWriteAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
    {
        DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;

        if ((ftracker != nullptr) && ftracker->is_ipc
            && (ftracker->fp_writex_raw != nullptr))
        {
            ftracker->fp_writex_raw->remaining = 0;
            DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
        }

        return DCE2_RET__ERROR;
    }

    if (DCE2_ComInfoIsRequest(com_info)
        && (SmbWriteAndXReqStartRaw((SmbWriteAndXReq*)nb_ptr)
        || SmbWriteAndXReqRaw((SmbWriteAndXReq*)nb_ptr)))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbGetFileTracker(ssd, SmbWriteAndXReqFid((SmbWriteAndXReq*)nb_ptr));

        // Raw mode is only applicable to named pipes.
        if ((ftracker != nullptr) && ftracker->is_ipc)
            return DCE2_SmbWriteAndXRawRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t fid = SmbWriteAndXReqFid((SmbWriteAndXReq*)nb_ptr);
        uint16_t doff = SmbWriteAndXReqDataOff((SmbWriteAndXReq*)nb_ptr);
        uint32_t dcnt = SmbWriteAndXReqDataCnt((SmbWriteAndXReq*)nb_ptr);
        uint64_t offset = SmbWriteAndXReqOffset((SmbWriteAndXExtReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
        {
            // Current Samba errors if data count is greater than data left
            if (DCE2_SsnGetPolicy(&ssd->sd) == DCE2_POLICY__SAMBA)
                return DCE2_RET__ERROR;

            // Windows and early Samba just use what's left
            dcnt = nb_len;
        }

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, offset);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_ANDX - raw mode
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DebugMessage(DEBUG_DCE_SMB,
        "Processing WriteAndX with raw mode flags\n");

    // Set this now for possible reassembled packet
    uint16_t fid = SmbWriteAndXReqFid((SmbWriteAndXReq*)nb_ptr);
    DCE2_SmbFileTracker* ftracker = DCE2_SmbGetFileTracker(ssd, fid);
    ssd->cur_rtracker->ftracker = ftracker;
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    // Got request to write in raw mode without having gotten the initial
    // raw mode request or got initial raw mode request and then another
    // without having finished the first.
    bool start_write_raw = SmbWriteAndXReqStartRaw((SmbWriteAndXReq*)nb_ptr);
    bool continue_write_raw = SmbWriteAndXReqRaw((SmbWriteAndXReq*)nb_ptr);
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    if ((start_write_raw && (ftracker->fp_writex_raw != nullptr)
        && (ftracker->fp_writex_raw->remaining != 0))
        || (continue_write_raw && ((ftracker->fp_writex_raw == nullptr)
        || (ftracker->fp_writex_raw->remaining == 0))))
    {
        switch (policy)
        {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            if (ftracker->fp_writex_raw != nullptr)
            {
                ftracker->fp_writex_raw->remaining = 0;
                DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
            }
            return DCE2_RET__ERROR;
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            // Samba doesn't do anything special here except if the two
            // flags are set it walks past the two "length" bytes.
            // See below.
            break;
        default:
            DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
                __FILE__, __LINE__, policy);
            break;
        }
    }

    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint16_t doff = SmbWriteAndXReqDataOff((SmbWriteAndXReq*)nb_ptr);
    uint32_t dcnt = SmbWriteAndXReqDataCnt((SmbWriteAndXReq*)nb_ptr);
    uint16_t remaining = SmbWriteAndXReqRemaining((SmbWriteAndXReq*)nb_ptr);

    DCE2_MOVE(nb_ptr, nb_len, com_size);

    if (DCE2_SmbCheckData(ssd, (uint8_t*)smb_hdr, nb_ptr, nb_len,
        byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    // This may move backwards
    DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

    // If a "raw" write is requested there will be two bytes after the
    // header/pad and before the data which is supposed to represent a
    // length but everyone ignores it.  However we need to move past it.
    // This is the one situation where the remaining field matters and
    // should be equal to the total amount of data to be written.
    if (start_write_raw)
    {
        if (dcnt < 2)
            return DCE2_RET__ERROR;

        // From data size check above, nb_len >= dsize
        dcnt -= 2;
        DCE2_MOVE(nb_ptr, nb_len, 2);
    }

    if (dcnt > nb_len)
        dcnt = nb_len;

    // File tracker already validated
    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        if (start_write_raw)
        {
            if (ftracker->fp_writex_raw == nullptr)
            {
                ftracker->fp_writex_raw = (DCE2_SmbWriteAndXRaw*)
                    snort_calloc(sizeof(DCE2_SmbWriteAndXRaw));
                if (ftracker->fp_writex_raw == nullptr)
                    return DCE2_RET__ERROR;

                ftracker->fp_writex_raw->remaining = (int)remaining;
            }
        }

        ftracker->fp_writex_raw->remaining -= (int)dcnt;
        if (ftracker->fp_writex_raw->remaining < 0)
        {
            ftracker->fp_writex_raw->remaining = 0;
            DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
            return DCE2_RET__ERROR;
        }

        // If the "raw" write isn't finished in the first request
        // and haven't allocated a buffer yet.
        if (start_write_raw && (ftracker->fp_writex_raw->remaining != 0)
            && (ftracker->fp_writex_raw->buf == nullptr))
        {
            ftracker->fp_writex_raw->buf =
                DCE2_BufferNew(remaining, 0);
            if (ftracker->fp_writex_raw->buf == nullptr)
            {
                ftracker->fp_writex_raw->remaining = 0;
                return DCE2_RET__ERROR;
            }
        }

        // If data has to be added to buffer, i.e. not a start raw
        // or a start raw and more raw requests to come.
        if (!start_write_raw || (ftracker->fp_writex_raw->remaining != 0))
        {
            if (DCE2_BufferAddData(ftracker->fp_writex_raw->buf, nb_ptr,
                dcnt, DCE2_BufferLength(ftracker->fp_writex_raw->buf),
                DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
            {
                ftracker->fp_writex_raw->remaining = 0;
                DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
                return DCE2_RET__ERROR;
            }

            if (ftracker->fp_writex_raw->remaining == 0)
            {
                //FIXIT-M  - port Create reassembled packet
/*
                    const uint8_t *data_ptr = DCE2_BufferData(ftracker->fp_writex_raw->buf);
                    uint32_t data_len = DCE2_BufferLength(ftracker->fp_writex_raw->buf);
                    SFSnortPacket *rpkt = DCE2_SmbGetRpkt(ssd,
                            &data_ptr, &data_len, DCE2_RPKT_TYPE__SMB_TRANS);

                    if (rpkt == nullptr)
                    {
                        DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
                        return DCE2_RET__ERROR;
                    }

                    DebugMessage(DEBUG_DCE_SMB,
                                "Reassembled WriteAndX raw mode request\n"));
                    DCE2_DEBUG_CODE(DCE2_DEBUG__MAIN, DCE2_PrintPktData(rpkt->payload, rpkt->payload_size););

                    (void)DCE2_SmbProcessRequestData(ssd, fid, data_ptr, data_len, 0);

                    DCE2_SmbReturnRpkt();
                    DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
*/
            }
        }
        else
        {
            (void)DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, 0);
        }

        // Windows doesn't process chained commands to raw WriteAndXs
        // so return error so it exits the loop.
        return DCE2_RET__ERROR;

    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
    case DCE2_POLICY__SAMBA_3_0_20:
        // All Samba cares about is skipping the 2 byte "length"
        // if both flags are set.
        break;
    default:
        DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
            __FILE__, __LINE__, policy);
        break;
    }

    return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, 0);
}

// SMB_COM_SESSION_SETUP_ANDX
static DCE2_Ret DCE2_SmbSessionSetupAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t max_multiplex =
            SmbSessionSetupAndXReqMaxMultiplex((SmbLm10_SessionSetupAndXReq*)nb_ptr);

        if (max_multiplex < ssd->max_outstanding_requests)
            ssd->max_outstanding_requests = max_multiplex;

        // FIXIT-M port fingerprint related code
    }
    else
    {
        uint16_t uid = SmbUid(smb_hdr);

        DCE2_SmbInsertUid(ssd, uid);
        ssd->cur_rtracker->uid = uid;  // Set this in case there are chained commands

        if (!(ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__NEGOTIATED))
            ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        // FIXIT-M port fingerprint related code
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NEGOTIATE
static DCE2_Ret DCE2_SmbNegotiate(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    Profile profile(dce2_smb_pstat_smb_negotiate);

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // FIXIT-M add dialect related code
    }
    else
    {
        // FIXIT-M add dialect related code

        ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        if (DCE2_ComInfoWordCount(com_info) == 17)
        {
            ssd->max_outstanding_requests =
                SmbNt_NegotiateRespMaxMultiplex((SmbNt_NegotiateProtocolResp*)nb_ptr);
        }
        else if (DCE2_ComInfoWordCount(com_info) == 13)
        {
            ssd->max_outstanding_requests =
                SmbLm_NegotiateRespMaxMultiplex((SmbLm10_NegotiateProtocolResp*)nb_ptr);
        }
        else
        {
            ssd->max_outstanding_requests = 1;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_CONNECT_ANDX

#define SERVICE_0     (0)                // IPC start
#define SERVICE_1     (SERVICE_0+4)      // DISK start
#define SERVICE_FS    (SERVICE_1+3)      // Failure
#define SERVICE_IPC   (SERVICE_FS+1)     // IPC service
#define SERVICE_DISK  (SERVICE_FS+2)     // DISK service

static const DCE2_SmbFsm dce2_smb_service_fsm[] =
{
    // IPC
    { 'I',  SERVICE_0+1, SERVICE_1 },
    { 'P',  SERVICE_0+2, SERVICE_FS },
    { 'C',  SERVICE_0+3, SERVICE_FS },
    { '\0', SERVICE_IPC, SERVICE_FS },

    // DISK
    { 'A',  SERVICE_1+1, SERVICE_FS },
    { ':',  SERVICE_1+2, SERVICE_FS },
    { '\0', SERVICE_DISK, SERVICE_FS },

    { 0, SERVICE_FS, SERVICE_FS }
};

static DCE2_Ret DCE2_SmbTreeConnectAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        if (DCE2_ScSmbInvalidShares((dce2SmbProtoConf*)ssd->sd.config) != nullptr)
        {
            uint16_t pass_len = SmbTreeConnectAndXReqPassLen((SmbTreeConnectAndXReq*)nb_ptr);
            DCE2_MOVE(nb_ptr, nb_len, com_size);
            if (pass_len >= nb_len)
                return DCE2_RET__ERROR;

            // Move past password length
            DCE2_MOVE(nb_ptr, nb_len, pass_len);

            const uint8_t* bs = nullptr;
            // Move past path components
            while ((bs = (const uint8_t*)memchr(nb_ptr, '\\', nb_len)) != nullptr)
                DCE2_MOVE(nb_ptr, nb_len, (bs - nb_ptr) + 1);

            // Move past NULL byte if unicode
            if (SmbUnicode(smb_hdr) && (nb_len != 0))
                DCE2_MOVE(nb_ptr, nb_len, 1);

            if (nb_len != 0)
                DCE2_SmbInvalidShareCheck(ssd, smb_hdr, nb_ptr, nb_len);
        }
    }
    else
    {
        DCE2_MOVE(nb_ptr, nb_len, com_size);

        int state = SERVICE_0;
        while ((nb_len > 0) && (state < SERVICE_FS))
        {
            if (dce2_smb_service_fsm[state].input == (char)*nb_ptr)
            {
                state = dce2_smb_service_fsm[state].next_state;
                DCE2_MOVE(nb_ptr, nb_len, 1);
            }
            else
            {
                state = dce2_smb_service_fsm[state].fail_state;
            }
        }

        uint16_t tid = SmbTid(smb_hdr);
        bool is_ipc = true;
        switch (state)
        {
        case SERVICE_IPC:
            DebugFormat(DEBUG_DCE_SMB,
                "Tid (%u) is an IPC tree.\n", tid);
            break;
        case SERVICE_DISK:
            is_ipc = false;
            DebugFormat(DEBUG_DCE_SMB,
                "Tid (%u) is a DISK tree.\n", tid);
            break;
        default:
            return DCE2_RET__IGNORE;
        }

        // Insert tid into list
        DCE2_SmbInsertTid(ssd, tid, is_ipc);
        ssd->cur_rtracker->tid = tid;  // Set this in case there are chained commands
    }

    return DCE2_RET__SUCCESS;
}

#define SHARE_0     (0)
#define SHARE_FS    (SHARE_0+5)
#define SHARE_IPC   (SHARE_FS+1)

static const DCE2_SmbFsm dce2_ipc_share_fsm[] =
{
    { 'I', SHARE_0+1, SHARE_FS },
    { 'P', SHARE_0+2, SHARE_FS },
    { 'C', SHARE_0+3, SHARE_FS },
    { '$', SHARE_0+4, SHARE_FS },
    { '\0', SHARE_IPC, SHARE_FS },

    { 0, SHARE_FS, SHARE_FS }
};

// SMB_COM_TREE_CONNECT
static DCE2_Ret DCE2_SmbTreeConnect(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);

        // Have at least 4 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        // If unicode flag is set, strings, except possibly the service string
        // are going to be unicode.  The NT spec specifies that unicode strings
        // must be word aligned with respect to the beginning of the SMB and that for
        // type-prefixed strings (this case), the padding byte is found after the
        // type format byte.

        // This byte will realign things.
        if (*nb_ptr != SMB_FMT__ASCII)
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        // IPC$ does not need to be case sensitive.  And the case sensitivity flag in
        // the SMB header doesn't seem to have any effect on this.
        const uint8_t* bs = nullptr;
        while ((bs = (const uint8_t*)memchr(nb_ptr, '\\', nb_len)) != nullptr)
            DCE2_MOVE(nb_ptr, nb_len, (bs - nb_ptr) + 1);

        bool unicode = SmbUnicode(smb_hdr);
        if (unicode && (nb_len > 0))
            DCE2_MOVE(nb_ptr, nb_len, 1);

        // Check for invalid shares first
        if ((DCE2_ScSmbInvalidShares((dce2SmbProtoConf*)ssd->sd.config) != nullptr) && (nb_len >
            0))
            DCE2_SmbInvalidShareCheck(ssd, smb_hdr, nb_ptr, nb_len);

        int state = SHARE_0;
        uint8_t increment = unicode ? 2 : 1;
        while ((nb_len >= increment) && (state < SHARE_FS))
        {
            if (dce2_ipc_share_fsm[state].input == toupper((int)nb_ptr[0]))
            {
                if (unicode && (nb_ptr[1] != 0))
                    break;
                state = dce2_ipc_share_fsm[state].next_state;
                DCE2_MOVE(nb_ptr, nb_len, increment);
            }
            else
            {
                state = dce2_ipc_share_fsm[state].fail_state;
            }
        }

        bool is_ipc = false;
        switch (state)
        {
        case SHARE_IPC:
            is_ipc = true;
            break;
        case SHARE_FS:
        default:
            break;
        }

        ssd->cur_rtracker->is_ipc = is_ipc;
    }
    else
    {
        // FIXIT-L What if the TID in the SMB header differs from that returned
        // in the TreeConnect command response?
        uint16_t tid = SmbTid(smb_hdr);
        DCE2_SmbInsertTid(ssd, tid, ssd->cur_rtracker->is_ipc);

        DebugFormat(DEBUG_DCE_SMB, "Tid (%u) %s an IPC tree\n", tid,
            (ssd->cur_rtracker->is_ipc) ? "is" : "is not");
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NT_CREATE_ANDX
static DCE2_Ret DCE2_SmbNtCreateAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        const uint16_t fid = SmbNtCreateAndXRespFid((SmbNtCreateAndXResp*)nb_ptr);
        DCE2_SmbFileTracker* ftracker = nullptr;

        // Set request tracker's current file tracker in case of chained commands
        switch (SmbAndXCom2((SmbAndXCommon*)nb_ptr))
        {
        // This is in case in the request a write was chained to an open
        // in which case the write will be to the newly opened file
        case SMB_COM_WRITE:
        case SMB_COM_WRITE_ANDX:
        case SMB_COM_TRANSACTION:
        case SMB_COM_READ_ANDX:
            ftracker = DCE2_SmbDequeueTmpFileTracker(ssd, ssd->cur_rtracker, fid);
            break;
        default:
            break;
        }

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            const bool is_directory = SmbNtCreateAndXRespDirectory((SmbNtCreateAndXResp*)nb_ptr);
            const uint16_t resource_type =
                SmbNtCreateAndXRespResourceType((SmbNtCreateAndXResp*)nb_ptr);

            if (is_directory || !SmbResourceTypeDisk(resource_type))
            {
                if (ftracker != nullptr)
                    DCE2_SmbRemoveFileTracker(ssd, ftracker);
                return DCE2_RET__SUCCESS;
            }

            // Give preference to files opened with the sequential only flag set
// FIXIT-M uncomment once fileApi is ported
/*
            if (((ssd->fapi_ftracker == nullptr) || !ssd->fapi_ftracker->ff_sequential_only)
                    && (ftracker == nullptr) && ssd->cur_rtracker->sequential_only)
            {
                DCE2_SmbAbortFileAPI(ssd);
            }
*/
        }

        if (ftracker == nullptr)
        {
            ftracker = DCE2_SmbNewFileTracker(ssd,
                ssd->cur_rtracker->uid, ssd->cur_rtracker->tid, fid);
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;
        }

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        DebugFormat(DEBUG_DCE_SMB, "File name: %s\n",
            (ftracker->file_name == nullptr) ? "nullptr" : ftracker->file_name);

        if (!ftracker->is_ipc)
        {
            const uint32_t create_disposition =
                SmbNtCreateAndXRespCreateDisposition((SmbNtCreateAndXResp*)nb_ptr);

            if (SmbCreateDispositionRead(create_disposition))
            {
                ftracker->ff_file_size =
                    SmbNtCreateAndXRespEndOfFile((SmbNtCreateAndXResp*)nb_ptr);
            }
            else
            {
                ftracker->ff_file_size = ssd->cur_rtracker->file_size;
                ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
            }

            ftracker->ff_sequential_only = ssd->cur_rtracker->sequential_only;
        }

        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        bool is_ipc = DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid);
        uint8_t smb_com2 = SmbAndXCom2((SmbAndXCommon*)nb_ptr);
        uint16_t file_name_length =
            SmbNtCreateAndXReqFileNameLen((SmbNtCreateAndXReq*)nb_ptr);

        if (!is_ipc)
        {
            uint32_t ext_file_attrs =
                SmbNtCreateAndXReqFileAttrs((SmbNtCreateAndXReq*)nb_ptr);

            if (SmbEvasiveFileAttrs(ext_file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
            // If the file is going to be accessed sequentially, track it.
            if (SmbNtCreateAndXReqSequentialOnly((SmbNtCreateAndXReq*)nb_ptr))
                ssd->cur_rtracker->sequential_only = true;

            ssd->cur_rtracker->file_size = SmbNtCreateAndXReqAllocSize(
                (SmbNtCreateAndXReq*)nb_ptr);
        }

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (file_name_length > DCE2_SMB_MAX_PATH_LEN)
            return DCE2_RET__ERROR;

        uint32_t pad = 0;
        const bool unicode = SmbUnicode(smb_hdr);
        if (unicode)
            pad = (nb_ptr - (const uint8_t*)smb_hdr) & 1;

        if (nb_len < (pad + file_name_length))
            return DCE2_RET__ERROR;

        DCE2_MOVE(nb_ptr, nb_len, pad);

        // Samba allows chaining OpenAndX/NtCreateAndX so might have
        // already been set.
        if (ssd->cur_rtracker->file_name == nullptr)
        {
            ssd->cur_rtracker->file_name =
                DCE2_SmbGetString(nb_ptr, file_name_length, unicode, false);
        }

        if (is_ipc)
        {
            switch (smb_com2)
            {
            case SMB_COM_READ_ANDX:
                if (DCE2_SsnIsWindowsPolicy(&ssd->sd))
                    return DCE2_RET__ERROR;
                break;
            default:
                break;
            }
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_DISCONNECT
static DCE2_Ret DCE2_SmbTreeDisconnect(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t*, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
        DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);

    return DCE2_RET__SUCCESS;
}

// SMB_COM_LOGOFF_ANDX
static DCE2_Ret DCE2_SmbLogoffAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t*, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbRemoveUid(ssd, ssd->cur_rtracker->uid);

        switch (DCE2_SsnGetServerPolicy(&ssd->sd))
        {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            /* Windows responds to a chained LogoffAndX => SessionSetupAndX with a
             * word count 3 LogoffAndX without the chained SessionSetupAndX */
            if (DCE2_ComInfoWordCount(com_info) == 3)
            {
                uint16_t uid = SmbUid(smb_hdr);
                DCE2_SmbInsertUid(ssd, uid);
                ssd->cur_rtracker->uid = uid;      // Set this in case there are chained commands
            }
            break;
        default:
            break;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TRANSACTION Request
static DCE2_Ret DCE2_SmbTransactionReq(DCE2_SmbSsnData* ssd,
    DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* data_ptr, uint32_t data_len,
    const uint8_t* param_ptr, uint32_t param_len)
{
    switch (ttracker->subcom)
    {
    case TRANS_TRANSACT_NMPIPE:
    case TRANS_WRITE_NMPIPE:
        if (DCE2_SmbProcessRequestData(ssd, 0,
            data_ptr, data_len, 0) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
        break;

    case TRANS_SET_NMPIPE_STATE:
        // Only two parameters but more seems okay
        if (param_len >= 2)
        {
            if ((alignedNtohs((uint16_t*)param_ptr) & PIPE_STATE_MESSAGE_MODE))
                ttracker->pipe_byte_mode = false;
            else
                ttracker->pipe_byte_mode = true;

            // Won't get a response
            if (DCE2_SsnIsWindowsPolicy(&ssd->sd) && ttracker->one_way)
            {
                DebugFormat(DEBUG_DCE_SMB,
                    "Setting pipe to %s mode\n",
                    ttracker->pipe_byte_mode ? "byte" : "message");

                ssd->cur_rtracker->ftracker->fp_byte_mode = ttracker->pipe_byte_mode;
            }
        }
        break;

    case TRANS_READ_NMPIPE:
        break;

    default:
        return DCE2_RET__IGNORE;
    }

    if (DCE2_SsnIsWindowsPolicy(&ssd->sd) && ttracker->one_way && ttracker->disconnect_tid)
        DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TRANSACTION

#define TRANS_NM_PIPE_0       (0)
#define TRANS_NM_PIPE_1       (TRANS_NM_PIPE_0+7)
#define TRANS_NM_PIPE_2       (TRANS_NM_PIPE_1+1)
#define TRANS_NM_PIPE_3       (TRANS_NM_PIPE_2+1)
#define TRANS_NM_PIPE_4       (TRANS_NM_PIPE_3+5)
#define TRANS_NM_PIPE_5       (TRANS_NM_PIPE_4+5)
#define TRANS_NM_PIPE_6       (TRANS_NM_PIPE_5+1)
#define TRANS_NM_PIPE_7       (TRANS_NM_PIPE_6+5)
#define TRANS_NM_PIPE_8       (TRANS_NM_PIPE_7+3)
#define TRANS_NM_PIPE_9       (TRANS_NM_PIPE_8+6)
#define TRANS_NM_PIPE_FS      (TRANS_NM_PIPE_9+1)
#define TRANS_NM_PIPE_DONE    (TRANS_NM_PIPE_FS+1)

static const DCE2_SmbFsm dce2_samba_pipe_fsm[] =
{
    // Normal sequence
    { '\\', TRANS_NM_PIPE_0+1, TRANS_NM_PIPE_FS },
    { 'P', TRANS_NM_PIPE_0+2, TRANS_NM_PIPE_FS },
    { 'I', TRANS_NM_PIPE_0+3, TRANS_NM_PIPE_FS },
    { 'P', TRANS_NM_PIPE_0+4, TRANS_NM_PIPE_FS },
    { 'E', TRANS_NM_PIPE_0+5, TRANS_NM_PIPE_FS },
    { '\\', TRANS_NM_PIPE_0+6, TRANS_NM_PIPE_1 },
    { '\0', TRANS_NM_PIPE_DONE, TRANS_NM_PIPE_2 },

    // Win98
    { '\0', TRANS_NM_PIPE_DONE, TRANS_NM_PIPE_FS },

    { 'W', TRANS_NM_PIPE_2+1, TRANS_NM_PIPE_5 },

    { 'K', TRANS_NM_PIPE_3+1, TRANS_NM_PIPE_4 },
    { 'S', TRANS_NM_PIPE_3+2, TRANS_NM_PIPE_FS },
    { 'S', TRANS_NM_PIPE_3+3, TRANS_NM_PIPE_FS },
    { 'V', TRANS_NM_PIPE_3+4, TRANS_NM_PIPE_FS },
    { 'C', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'I', TRANS_NM_PIPE_4+1, TRANS_NM_PIPE_FS },
    { 'N', TRANS_NM_PIPE_4+2, TRANS_NM_PIPE_FS },
    { 'R', TRANS_NM_PIPE_4+3, TRANS_NM_PIPE_FS },
    { 'E', TRANS_NM_PIPE_4+4, TRANS_NM_PIPE_FS },
    { 'G', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'S', TRANS_NM_PIPE_5+1, TRANS_NM_PIPE_8 },

    { 'R', TRANS_NM_PIPE_6+1, TRANS_NM_PIPE_5 },
    { 'V', TRANS_NM_PIPE_6+2, TRANS_NM_PIPE_FS },
    { 'S', TRANS_NM_PIPE_6+3, TRANS_NM_PIPE_FS },
    { 'V', TRANS_NM_PIPE_6+4, TRANS_NM_PIPE_FS },
    { 'C', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'A', TRANS_NM_PIPE_7+1, TRANS_NM_PIPE_FS },
    { 'M', TRANS_NM_PIPE_7+2, TRANS_NM_PIPE_FS },
    { 'R', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'L', TRANS_NM_PIPE_8+1, TRANS_NM_PIPE_FS },
    { 'S', TRANS_NM_PIPE_8+2, TRANS_NM_PIPE_FS },
    { 'A', TRANS_NM_PIPE_8+3, TRANS_NM_PIPE_FS },
    { 'R', TRANS_NM_PIPE_8+4, TRANS_NM_PIPE_FS },
    { 'P', TRANS_NM_PIPE_8+5, TRANS_NM_PIPE_FS },
    { 'C', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { '\0', TRANS_NM_PIPE_DONE, TRANS_NM_PIPE_FS },

    { 0, TRANS_NM_PIPE_FS, TRANS_NM_PIPE_FS }
};

// Validates Name for Samba Transaction requests
static DCE2_Ret DCE2_SmbTransactionGetName(const uint8_t* nb_ptr,
    uint32_t nb_len, uint16_t bcc, bool unicode)
{
    if ((nb_len == 0) || (bcc == 0))
        return DCE2_RET__ERROR;

    if (bcc < nb_len)
        nb_len = bcc;

    if (unicode)
        DCE2_MOVE(nb_ptr, nb_len, 1);  // One byte pad for unicode

    uint8_t increment = unicode ? 2 : 1;
    int state = TRANS_NM_PIPE_0;
    while ((nb_len >= increment) && (state < TRANS_NM_PIPE_FS))
    {
        if (dce2_samba_pipe_fsm[state].input == toupper((int)nb_ptr[0]))
        {
            if (unicode && (nb_ptr[1] != 0))
                break;
            state = dce2_samba_pipe_fsm[state].next_state;
            DCE2_MOVE(nb_ptr, nb_len, increment);
        }
        else
        {
            state = dce2_samba_pipe_fsm[state].fail_state;
        }
    }

    switch (state)
    {
    case TRANS_NM_PIPE_DONE:
        break;
    case TRANS_NM_PIPE_FS:
    default:
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

static DCE2_Ret DCE2_SmbTransaction(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;

    // Got a matching request for an in progress transaction - don't process it,
    // but don't want to remove tracker.
    if (DCE2_ComInfoIsRequest(com_info)
        && !DCE2_SmbIsTransactionComplete(ttracker))
    {
        DebugMessage(DEBUG_DCE_SMB, "Got new transaction request "
            "that matches an in progress transaction - not inspecting.\n");
        return DCE2_RET__ERROR;
    }

    // Avoid decoding/tracking \PIPE\LANMAN requests
    if (DCE2_ComInfoIsRequest(com_info)
        && (DCE2_ComInfoWordCount(com_info) != 16))
    {
        DebugMessage(DEBUG_DCE_SMB, "\\PIPE\\LANMAN request - not inspecting\n");
        return DCE2_RET__IGNORE;
    }

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    // Interim response is sent if client didn't send all data / parameters
    // in initial Transaction request and will have to complete the request
    // with TransactionSecondary commands.
    if (DCE2_ComInfoIsResponse(com_info)
        && (com_size == sizeof(SmbTransactionInterimResp)))
    {
        DebugMessage(DEBUG_DCE_SMB,
            "  Server Transaction interim response.\n");

        return DCE2_RET__SUCCESS;
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_Ret status =
            DCE2_SmbUpdateTransRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        ttracker->disconnect_tid = SmbTransactionReqDisconnectTid((SmbTransactionReq*)nb_ptr);
        ttracker->one_way = SmbTransactionReqOneWay((SmbTransactionReq*)nb_ptr);

        uint16_t doff = SmbTransactionReqDataOff((SmbTransactionReq*)nb_ptr);
        uint16_t dcnt = SmbTransactionReqDataCnt((SmbTransactionReq*)nb_ptr);
        uint16_t pcnt = SmbTransactionReqParamCnt((SmbTransactionReq*)nb_ptr);
        uint16_t poff = SmbTransactionReqParamOff((SmbTransactionReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);
        const uint8_t* data_ptr = nb_ptr;

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);
        const uint8_t* param_ptr = nb_ptr;

        status = DCE2_SmbTransactionReq(ssd, ttracker, data_ptr, dcnt, param_ptr, pcnt);
        if (status != DCE2_RET__SUCCESS)
            return status;
    }
    else
    {
        DCE2_Ret status =
            DCE2_SmbUpdateTransResponse(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        switch (ttracker->subcom)
        {
        case TRANS_TRANSACT_NMPIPE:
        case TRANS_READ_NMPIPE:
        {
            // FIXIT-M port reassembly case

            uint16_t dcnt = SmbTransactionRespDataCnt((SmbTransactionResp*)nb_ptr);
            uint16_t doff = SmbTransactionRespDataOff((SmbTransactionResp*)nb_ptr);

            DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

            if (DCE2_SmbProcessResponseData(ssd, nb_ptr, dcnt) != DCE2_RET__SUCCESS)
                return DCE2_RET__ERROR;

            break;
        }
        case TRANS_SET_NMPIPE_STATE:
            DebugFormat(DEBUG_DCE_SMB, "Setting pipe "
                "to %s mode\n", ttracker->pipe_byte_mode ? "byte" : "message");
            ssd->cur_rtracker->ftracker->fp_byte_mode = ttracker->pipe_byte_mode;
            break;

        case TRANS_WRITE_NMPIPE:
            break;

        default:
            return DCE2_RET__ERROR;
        }

        if (ttracker->disconnect_tid)
            DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);
    }

    return DCE2_RET__SUCCESS;
}

#define DCE2_SMB_TRANS__NONE    0x00
#define DCE2_SMB_TRANS__DATA    0x01
#define DCE2_SMB_TRANS__PARAMS  0x02
#define DCE2_SMB_TRANS__BOTH    (DCE2_SMB_TRANS__DATA|DCE2_SMB_TRANS__PARAMS)

/********************************************************************
 * Function: DCE2_SmbUpdateTransRequest()
 *
 * Purpose:
 *  Handles common checks and updates of transaction requests -
 *  SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2 and SMB_COM_NT_TRANSACT
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - pointer to SMB session data
 *  const SmbNtHdr *        - pointer to SMB header
 *  const DCE2_SmbComInfo * - pointer to com info structure
 *  const uint8_t *         - pointer to data
 *  uint32_t                - data length
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__IGNORE if we don't process the subcommand
 *      DCE2_RET__FULL if the transaction is complete
 *      DCE2_RET__ERROR if an error occurred.
 *      DCE2_RET__SUCCESS if ok (but not complete).
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbUpdateTransRequest(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const DCE2_SmbComInfo* com_info,
    const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint32_t tpcnt, pcnt, poff;
    uint32_t tdcnt, dcnt, doff;
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint16_t fid;
    uint8_t setup_count;
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    uint16_t sub_com =0;
    int data_params = DCE2_SMB_TRANS__NONE;
    uint8_t smb_com = DCE2_ComInfoSmbCom(com_info);

    //FIXIT-M init to avoid warnings. can be removed once other commands are supported
    tpcnt =0; pcnt =0; poff =0;
    tdcnt =0; dcnt =0; doff =0;

    switch (smb_com)
    {
    case SMB_COM_TRANSACTION:
        sub_com = SmbTransactionReqSubCom((SmbTransactionReq*)nb_ptr);
        fid = SmbTransactionReqFid((SmbTransactionReq*)nb_ptr);
        setup_count = SmbTransactionReqSetupCnt((SmbTransactionReq*)nb_ptr);
        tdcnt = SmbTransactionReqTotalDataCnt((SmbTransactionReq*)nb_ptr);
        doff = SmbTransactionReqDataOff((SmbTransactionReq*)nb_ptr);
        dcnt = SmbTransactionReqDataCnt((SmbTransactionReq*)nb_ptr);
        tpcnt = SmbTransactionReqTotalParamCnt((SmbTransactionReq*)nb_ptr);
        pcnt = SmbTransactionReqParamCnt((SmbTransactionReq*)nb_ptr);
        poff = SmbTransactionReqParamOff((SmbTransactionReq*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Transaction subcommand: %s (0x%04X)\n",
            (sub_com < TRANS_SUBCOM_MAX)
            ? smb_transaction_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        ssd->cur_rtracker->ftracker = DCE2_SmbGetFileTracker(ssd, fid);
        if (ssd->cur_rtracker->ftracker == nullptr)
            return DCE2_RET__IGNORE;

        switch (sub_com)
        {
        case TRANS_TRANSACT_NMPIPE:
            if (DCE2_SsnIsWindowsPolicy(&ssd->sd)
                && ssd->cur_rtracker->ftracker->fp_byte_mode)
            {
                DebugMessage(DEBUG_DCE_SMB, "Pipe is in byte "
                    "mode - TRANS_TRANSACT_NMPIPE won't work\n");
                return DCE2_RET__ERROR;
            }
            data_params = DCE2_SMB_TRANS__DATA;
            break;

        case TRANS_READ_NMPIPE:
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
            break;

        case TRANS_SET_NMPIPE_STATE:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;

        case TRANS_WRITE_NMPIPE:
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
            data_params = DCE2_SMB_TRANS__DATA;
            break;

        // Not implemented according to MS-CIFS
        case TRANS_RAW_READ_NMPIPE:

        // Can only write 2 NULL bytes and subsequent writes return pipe disconnected
        case TRANS_RAW_WRITE_NMPIPE:

        // Can at most do a DCE/RPC bind
        case TRANS_CALL_NMPIPE:
            dce_alert(GID_DCE2, DCE2_SMB_DEPR_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
        // Aren't looking at these or the three above
        case TRANS_QUERY_NMPIPE_STATE:
        case TRANS_QUERY_NMPIPE_INFO:
        case TRANS_PEEK_NMPIPE:
        case TRANS_WAIT_NMPIPE:
        default:
            // Don't want to track the response
            return DCE2_RET__IGNORE;
        }

        // Servers return error if incorrect setup count
        if (setup_count != 2)
        {
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_SETUP_COUNT, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        // Samba validates the Name which should be \PIPE\ and errors
        // if not.  Windows doesn't care.
        // And Samba uses the ByteCount to validate
        if (DCE2_SsnIsSambaPolicy(&ssd->sd)
            && (DCE2_SmbTransactionGetName(nb_ptr, nb_len,
            byte_count, SmbUnicode(smb_hdr)) != DCE2_RET__SUCCESS))
        {
            DebugMessage(DEBUG_DCE_SMB, "Failed to validate "
                "pipe name for Samba.\n");
            return DCE2_RET__ERROR;
        }
        break;

    case SMB_COM_TRANSACTION2:
        // FIXIT-M port together with transaction2

        break;

    case SMB_COM_NT_TRANSACT:
        // FIXIT-M port together with nt_transact
        break;

    default:
        return DCE2_RET__ERROR;
    }

    if (DCE2_SmbValidateTransactionFields((uint8_t*)smb_hdr, nb_ptr, nb_len,
        byte_count, tdcnt, tpcnt, dcnt, doff, 0, pcnt, poff, 0) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    ttracker->smb_type = SMB_TYPE__REQUEST;
    ttracker->subcom = (uint8_t)sub_com;
    ttracker->tdcnt = tdcnt;
    ttracker->dsent = dcnt;
    ttracker->tpcnt = tpcnt;
    ttracker->psent = pcnt;

    DebugFormat(DEBUG_DCE_SMB, "Data count: %u, "
        "Total data count: %u, Param count: %u, "
        "Total param count: %u\n", dcnt, tdcnt, pcnt, tpcnt);

    // Testing shows that Transacts aren't processed until
    // all of the data and parameters are received, so overlapping
    // writes to the same FID can occur as long as the pid/mid are
    // distinct (and that depends on policy).  So we need to buffer
    // data up for each incomplete Transact so data doesn't get mangled
    // together with multiple ones intermixing at the same time.

    if (data_params & DCE2_SMB_TRANS__DATA)
    {
        // FIXIT-M port
    }

    if (data_params & DCE2_SMB_TRANS__PARAMS)
    {
        // FIXIT-M port
    }

    if ((dcnt == tdcnt) && (pcnt == tpcnt))
        return DCE2_RET__FULL;

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbUpdateTransResponse()
 *
 * Purpose:
 *  Handles common checks and updates of transaction responses -
 *  SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2 and SMB_COM_NT_TRANSACT
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - pointer to SMB session data
 *  const SmbNtHdr *        - pointer to SMB header
 *  const DCE2_SmbComInfo * - pointer to com info structure
 *  const uint8_t *         - pointer to data
 *  uint32_t                - data length
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__FULL if the transaction is complete
 *      DCE2_RET__ERROR if an error occurred.
 *      DCE2_RET__SUCCESS if ok (but not complete).
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbUpdateTransResponse(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const DCE2_SmbComInfo* com_info,
    const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint32_t tpcnt, pcnt, poff, pdisp;
    uint32_t tdcnt, dcnt, doff, ddisp;
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    uint16_t sub_com = ttracker->subcom;
    int data_params = DCE2_SMB_TRANS__NONE;
    uint8_t smb_com = DCE2_ComInfoSmbCom(com_info);

    //FIXIT-M init to avoid warnings. can be removed once other commands are supported
    tpcnt =0; pcnt =0; poff =0; pdisp =0;
    tdcnt =0; dcnt =0; doff =0; ddisp =0;
    switch (smb_com)
    {
    case SMB_COM_TRANSACTION:
        tdcnt = SmbTransactionRespTotalDataCnt((SmbTransactionResp*)nb_ptr);
        doff = SmbTransactionRespDataOff((SmbTransactionResp*)nb_ptr);
        dcnt = SmbTransactionRespDataCnt((SmbTransactionResp*)nb_ptr);
        ddisp = SmbTransactionRespDataDisp((SmbTransactionResp*)nb_ptr);
        tpcnt = SmbTransactionRespTotalParamCnt((SmbTransactionResp*)nb_ptr);
        pcnt = SmbTransactionRespParamCnt((SmbTransactionResp*)nb_ptr);
        poff = SmbTransactionRespParamOff((SmbTransactionResp*)nb_ptr);
        pdisp = SmbTransactionRespParamDisp((SmbTransactionResp*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Transaction subcommand: %s (0x%04X)\n",
            (sub_com < TRANS_SUBCOM_MAX)
            ? smb_transaction_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        switch (sub_com)
        {
        case TRANS_TRANSACT_NMPIPE:
        case TRANS_READ_NMPIPE:
            data_params = DCE2_SMB_TRANS__DATA;
            break;
        case TRANS_SET_NMPIPE_STATE:
        case TRANS_WRITE_NMPIPE:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        default:
            return DCE2_RET__ERROR;
        }

        break;

    case SMB_COM_TRANSACTION2:
        // FIXIT-M port along with transaction2

        break;

    case SMB_COM_NT_TRANSACT:
        // FIXIT-M port along with NT_TRANSACT

        break;

    default:
        return DCE2_RET__ERROR;
    }

    DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

    // From client request
    if (ttracker->smb_type == SMB_TYPE__REQUEST)
    {
        ttracker->smb_type = SMB_TYPE__RESPONSE;
        ttracker->tdcnt = tdcnt;
        ttracker->tpcnt = tpcnt;
        ttracker->dsent = 0;
        ttracker->psent = 0;
        DCE2_BufferDestroy(ttracker->dbuf);
        ttracker->dbuf = nullptr;
        DCE2_BufferDestroy(ttracker->pbuf);
        ttracker->pbuf = nullptr;
    }
    else
    {
        if (tdcnt < ttracker->tdcnt)
            ttracker->tdcnt = tdcnt;
        if (tpcnt < ttracker->tpcnt)
            ttracker->tpcnt = pcnt;
    }

    if (DCE2_SmbValidateTransactionFields((uint8_t*)smb_hdr, nb_ptr, nb_len,
        DCE2_ComInfoByteCount(com_info), tdcnt, tpcnt, dcnt, doff, ddisp,
        pcnt, poff, pdisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbValidateTransactionSent(ttracker->dsent, dcnt, ttracker->tdcnt,
        ttracker->psent, pcnt, ttracker->tpcnt) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    ttracker->dsent += dcnt;
    ttracker->psent += pcnt;

    DebugFormat(DEBUG_DCE_SMB, "Data displacement: %u, "
        "Data count: %u, Total data count: %u\n"
        "Parameter displacement: %u, "
        "Parameter count: %u, Total parameter count: %u\n",
        ddisp, dcnt, tdcnt, pdisp, pcnt, tpcnt);

    if (data_params & DCE2_SMB_TRANS__DATA)
    {
        // FIXIT-M port
    }

    if (data_params & DCE2_SMB_TRANS__PARAMS)
    {
        // FIXIT-M port
    }

    if ((ttracker->dsent == ttracker->tdcnt)
        && (ttracker->psent == ttracker->tpcnt))
    {
        return DCE2_RET__FULL;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbCheckTotalCount()
 *
 * Purpose:
 *  Validates the advertised total data/param count.  Makes sure the
 *  current count isn't greater than total count, that the
 *  displacement + count isn't greater than the total data count and
 *  that the total data count isn't zero.  Mainly relevant to Write Raw,
 *  Transaction and Transaction Secondary commands.
 *
 * Arguments:
 *  const uint32_t    - total data count
 *  const uint32_t    - data count/size
 *  const uint32_t    - data displacement
 *
 * Returns:
 *  DCE2_Ret - DCE2_RET__SUCCESS if all is ok
 *             DCE2_RET__ERROR if any of the checks fail.
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbCheckTotalCount(const uint32_t tcnt, const uint32_t cnt, const uint32_t
    disp)
{
    DCE2_Ret ret = DCE2_RET__SUCCESS;

    if (cnt > tcnt)
    {
        dce_alert(GID_DCE2, DCE2_SMB_TDCNT_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
        ret = DCE2_RET__ERROR;
    }

    if (((uint64_t)disp + cnt) > tcnt)
    {
        dce_alert(GID_DCE2, DCE2_SMB_DSENT_GT_TDCNT, (dce2CommonStats*)&dce2_smb_stats);
        ret = DCE2_RET__ERROR;
    }

    return ret;
}

/********************************************************************
 * Function: DCE2_SmbCheckTransDataParams()
 *
 * Purpose:
 *  Ensures that the data size reported in an SMB command is kosher.
 *  Note the 32 bit values are because of the NtTransact command
 *  though it's currently not checked.
 *
 * Arguments:
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count
 *  const uint32_t    - reported data count
 *  const uint32_t    - reported data offset
 *  const uint32_t    - reported parameter count
 *  const uint32_t    - reported parameter offset
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbCheckTransDataParams(
    const uint8_t* smb_hdr_ptr, const uint8_t* nb_ptr, const uint32_t nb_len,
    const uint16_t bcc, const uint32_t dcnt, const uint32_t doff,
    const uint32_t pcnt, const uint32_t poff)
{
    const uint8_t* doffset = smb_hdr_ptr + doff;
    const uint8_t* poffset = smb_hdr_ptr + poff;
    const uint8_t* nb_end = nb_ptr + nb_len;

    if (bcc < ((uint64_t)dcnt + pcnt))
        dce_alert(GID_DCE2, DCE2_SMB_BCC_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);

    // Check data offset out of bounds
    if ((doffset > nb_end) || (doffset < smb_hdr_ptr))
    {
        // Beyond data left or wrap
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    // Check data offset in bounds but backwards
    // Only check if the data count is non-zero
    if ((dcnt != 0) && (doffset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    // Check the data offset + data count
    if (((doffset + dcnt) > nb_end)            // beyond data left
        || ((doffset + dcnt) < doffset))       // wrap
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    // Check parameter offset out of bounds
    if ((poffset > nb_end) || (poffset < smb_hdr_ptr))
    {
        // Beyond data left or wrap
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    // Check parameter offset in bounds but backwards
    // Only check if the parameter count is non-zero
    if ((pcnt != 0) && (poffset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    // Check the parameter offset + parameter count
    if (((poffset + pcnt) > nb_end)            // beyond data left
        || ((poffset + pcnt) < poffset))       // wrap
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbValidateTransactionSent()
 *
 * Purpose:
 *  Checks that amount sent plus current amount is not greater than
 *  the total count expected.
 *
 * Arguments:
 *  const uint32_t    - amount of data sent so far
 *  const uint32_t    - reported total data count
 *  const uint32_t    - reported data count
 *  const uint32_t    - amount of parameters sent so far
 *  const uint32_t    - reported total parameter count
 *  const uint32_t    - reported parameter count
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbValidateTransactionSent(
    uint32_t dsent, uint32_t dcnt, uint32_t tdcnt,
    uint32_t psent, uint32_t pcnt, uint32_t tpcnt)
{
    if (((dsent + dcnt) > tdcnt) || ((psent + pcnt) > tpcnt))
    {
        if ((dsent + dcnt) > tdcnt)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DSENT_GT_TDCNT, (dce2CommonStats*)&dce2_smb_stats);
        }

        if ((psent + pcnt) > tpcnt)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DSENT_GT_TDCNT, (dce2CommonStats*)&dce2_smb_stats);
        }

        // Samba throws out entire transaction and Windows seems to hang in
        // limbo forever and never responds, so stop looking
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbValidateTransactionFields()
 *
 * Purpose:
 *  Wrapper that calls DCE2_SmbCheckTotalCount() for total parameter
 *  count and total data count and DCE2_SmbCheckTransDataParams()
 *
 * Arguments:
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count
 *  const uint32_t    - reported total data count
 *  const uint32_t    - reported total parameter count
 *  const uint32_t    - reported data count
 *  const uint32_t    - reported data offset
 *  const uint32_t    - reported data displacement
 *  const uint32_t    - reported parameter count
 *  const uint32_t    - reported parameter offset
 *  const uint32_t    - reported parameter displacement
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbValidateTransactionFields(
    const uint8_t* smb_hdr_ptr,
    const uint8_t* nb_ptr, const uint32_t nb_len, const uint16_t bcc,
    const uint32_t tdcnt, const uint32_t tpcnt,
    const uint32_t dcnt, const uint32_t doff, const uint32_t ddisp,
    const uint32_t pcnt, const uint32_t poff, const uint32_t pdisp)
{
    if (DCE2_SmbCheckTotalCount(tdcnt, dcnt, ddisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbCheckTotalCount(tpcnt, pcnt, pdisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbCheckTransDataParams(smb_hdr_ptr,
        nb_ptr, nb_len, bcc, dcnt, doff, pcnt, poff) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    return DCE2_RET__SUCCESS;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dce2Smb : public Inspector
{
public:
    Dce2Smb(dce2SmbProtoConf&);
    ~Dce2Smb();

    void show(SnortConfig*) override;
    void eval(Packet*) override;
    StreamSplitter* get_splitter(bool c2s) override
    {
        return new Dce2SmbSplitter(c2s);
    }

private:
    dce2SmbProtoConf config;
};

Dce2Smb::Dce2Smb(dce2SmbProtoConf& pc)
{
    config = pc;
}

Dce2Smb::~Dce2Smb()
{
    if (config.smb_invalid_shares)
    {
        DCE2_ListDestroy(config.smb_invalid_shares);
    }
}

void Dce2Smb::show(SnortConfig*)
{
    print_dce2_smb_conf(config);
}

void Dce2Smb::eval(Packet* p)
{
    DCE2_SmbSsnData* dce2_smb_sess;
    Profile profile(dce2_smb_pstat_main);

    assert(p->has_tcp_data());
    assert(p->flow);

    if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
    {
        DebugMessage(DEBUG_DCE_SMB,
            "Midstream - not inspecting.\n");
        return;
    }

    dce2_smb_sess = dce2_handle_smb_session(p, &config);
    if (dce2_smb_sess)
    {
        //FIXIT-L evaluate moving pushpkt out of session pstats
        if (DCE2_PushPkt(p,&dce2_smb_sess->sd) != DCE2_RET__SUCCESS)
        {
            DebugMessage(DEBUG_DCE_SMB, "Failed to push packet onto packet stack.\n");
            return;
        }
        p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
        dce2_detected = 0;

        p->endianness = (Endianness*)new DceEndianness();

        DCE2_SmbProcess(dce2_smb_sess);

        if (!dce2_detected)
            DCE2_Detect(&dce2_smb_sess->sd);

        DCE2_ResetRopts(&dce2_smb_sess->sd.ropts);
        DCE2_PopPkt(&dce2_smb_sess->sd);

        if (!DCE2_SsnAutodetected(&dce2_smb_sess->sd))
            DisableInspection();

        delete p->endianness;
        p->endianness = nullptr;
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Dce2SmbModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void dce2_smb_init()
{
    Dce2SmbFlowData::init();
    DCE2_SmbInitGlobals();
}

static Inspector* dce2_smb_ctor(Module* m)
{
    Dce2SmbModule* mod = (Dce2SmbModule*)m;
    dce2SmbProtoConf config;
    mod->get_data(config);
    return new Dce2Smb(config);
}

static void dce2_smb_dtor(Inspector* p)
{
    delete p;
}

static void dce2_smb_thread_init()
{
    if (dce2_inspector_instances == 0)
    {
        dce2_pkt_stack = DCE2_CStackNew(DCE2_PKT_STACK__SIZE, nullptr);
    }
    if (dce2_smb_inspector_instances == 0)
    {
        for (int i=0; i < DCE2_SMB_RPKT_TYPE_MAX; i++)
        {
            Packet* p = (Packet*)snort_calloc(sizeof(Packet));
            p->data = (uint8_t*)snort_calloc(DCE2_REASSEMBLY_BUF_SIZE);
            p->dsize = DCE2_REASSEMBLY_BUF_SIZE;
            dce2_smb_rpkt[i] = p;
        }
    }
    dce2_smb_inspector_instances++;
    dce2_inspector_instances++;
}

static void dce2_smb_thread_term()
{
    dce2_inspector_instances--;
    dce2_smb_inspector_instances--;

    if (dce2_smb_inspector_instances == 0)
    {
        for (int i=0; i<DCE2_SMB_RPKT_TYPE_MAX; i++)
        {
            if ( dce2_smb_rpkt[i] != nullptr )
            {
                Packet* p = dce2_smb_rpkt[i];
                if (p->data)
                {
                    snort_free((void*)p->data);
                }
                snort_free(p);
                dce2_smb_rpkt[i] = nullptr;
            }
        }
    }
    if (dce2_inspector_instances == 0)
    {
        DCE2_CStackDestroy(dce2_pkt_stack);
        dce2_pkt_stack = nullptr;
    }
}

const InspectApi dce2_smb_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DCE2_SMB_NAME,
        DCE2_SMB_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    nullptr,  // buffers
    "dce_smb",
    dce2_smb_init,
    nullptr, // pterm
    dce2_smb_thread_init, // tinit
    dce2_smb_thread_term, // tterm
    dce2_smb_ctor,
    dce2_smb_dtor,
    nullptr, // ssn
    nullptr  // reset
};

