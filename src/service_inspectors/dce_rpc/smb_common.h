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

// smb_common.h author Russ Combs <rucombs@cisco.com>

// extracted from dce_smb.h originally written by Todd Wease

#ifndef SMB_COMMON_H
#define SMB_COMMON_H

#include <cstdint>

#define SMB_MAX_NUM_COMS   256

#define SMB_FILE_TYPE_DISK               0x0000
#define SMB_FILE_TYPE_BYTE_MODE_PIPE     0x0001
#define SMB_FILE_TYPE_MESSAGE_MODE_PIPE  0x0002
#define SMB_FILE_TYPE_PRINTER            0x0003
#define SMB_FILE_TYPE_COMMON_DEVICE      0x0004

#define SMB_FILE_ATTRIBUTE_NORMAL       0x0000
#define SMB_FILE_ATTRIBUTE_READONLY     0x0001
#define SMB_FILE_ATTRIBUTE_HIDDEN       0x0002
#define SMB_FILE_ATTRIBUTE_SYSTEM       0x0004
#define SMB_FILE_ATTRIBUTE_VOLUME       0x0008
#define SMB_FILE_ATTRIBUTE_DIRECTORY    0x0010
#define SMB_FILE_ATTRIBUTE_ARCHIVE      0x0020
#define SMB_SEARCH_ATTRIBUTE_READONLY   0x0100
#define SMB_SEARCH_ATTRIBUTE_HIDDEN     0x0200
#define SMB_SEARCH_ATTRIBUTE_SYSTEM     0x0400
#define SMB_SEARCH_ATTRIBUTE_DIRECTORY  0x1000
#define SMB_SEARCH_ATTRIBUTE_ARCHIVE    0x2000
#define SMB_FILE_ATTRIBUTE_OTHER        0xC8C0   // Reserved

#define SMB_EXT_FILE_ATTR_READONLY    0x00000001
#define SMB_EXT_FILE_ATTR_HIDDEN      0x00000002
#define SMB_EXT_FILE_ATTR_SYSTEM      0x00000004
#define SMB_EXT_FILE_ATTR_DIRECTORY   0x00000010
#define SMB_EXT_FILE_ATTR_ARCHIVE     0x00000020
#define SMB_EXT_FILE_ATTR_NORMAL      0x00000080
#define SMB_EXT_FILE_ATTR_TEMPORARY   0x00000100
#define SMB_EXT_FILE_ATTR_COMPRESSED  0x00000800
#define SMB_EXT_FILE_POSIX_SEMANTICS  0x01000000
#define SMB_EXT_FILE_BACKUP_SEMANTICS 0x02000000
#define SMB_EXT_FILE_DELETE_ON_CLOSE  0x04000000
#define SMB_EXT_FILE_SEQUENTIAL_SCAN  0x08000000
#define SMB_EXT_FILE_RANDOM_ACCESS    0x10000000
#define SMB_EXT_FILE_NO_BUFFERING     0x20000000
#define SMB_EXT_FILE_WRITE_THROUGH    0x80000000

#define NBSS_SESSION_TYPE__MESSAGE            0x00
#define NBSS_SESSION_TYPE__REQUEST            0x81
#define NBSS_SESSION_TYPE__POS_RESPONSE       0x82
#define NBSS_SESSION_TYPE__NEG_RESPONSE       0x83
#define NBSS_SESSION_TYPE__RETARGET_RESPONSE  0x84
#define NBSS_SESSION_TYPE__KEEP_ALIVE         0x85

#define DCE2_SMB_ID   0xff534d42  /* \xffSMB */
#define DCE2_SMB2_ID  0xfe534d42  /* \xfeSMB */

// MS-FSCC Section 2.1.5 - Pathname
#define DCE2_SMB_MAX_PATH_LEN  32760
#define DCE2_SMB_MAX_COMP_LEN    255

/* SMB command codes */
#define SMB_COM_CREATE_DIRECTORY 0x00
#define SMB_COM_DELETE_DIRECTORY 0x01
#define SMB_COM_OPEN 0x02
#define SMB_COM_CREATE 0x03
#define SMB_COM_CLOSE 0x04
#define SMB_COM_FLUSH 0x05
#define SMB_COM_DELETE 0x06
#define SMB_COM_RENAME 0x07
#define SMB_COM_QUERY_INFORMATION 0x08
#define SMB_COM_SET_INFORMATION 0x09
#define SMB_COM_READ 0x0A
#define SMB_COM_WRITE 0x0B
#define SMB_COM_LOCK_BYTE_RANGE 0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE 0x0D
#define SMB_COM_CREATE_TEMPORARY 0x0E
#define SMB_COM_CREATE_NEW 0x0F
#define SMB_COM_CHECK_DIRECTORY 0x10
#define SMB_COM_PROCESS_EXIT 0x11
#define SMB_COM_SEEK 0x12
#define SMB_COM_LOCK_AND_READ 0x13
#define SMB_COM_WRITE_AND_UNLOCK 0x14
#define SMB_COM_READ_RAW 0x1A
#define SMB_COM_READ_MPX 0x1B
#define SMB_COM_READ_MPX_SECONDARY 0x1C
#define SMB_COM_WRITE_RAW 0x1D
#define SMB_COM_WRITE_MPX 0x1E
#define SMB_COM_WRITE_MPX_SECONDARY 0x1F
#define SMB_COM_WRITE_COMPLETE 0x20
#define SMB_COM_QUERY_SERVER 0x21
#define SMB_COM_SET_INFORMATION2 0x22
#define SMB_COM_QUERY_INFORMATION2 0x23
#define SMB_COM_LOCKING_ANDX 0x24
#define SMB_COM_TRANSACTION 0x25
#define SMB_COM_TRANSACTION_SECONDARY 0x26
#define SMB_COM_IOCTL 0x27
#define SMB_COM_IOCTL_SECONDARY 0x28
#define SMB_COM_COPY 0x29
#define SMB_COM_MOVE 0x2A
#define SMB_COM_ECHO 0x2B
#define SMB_COM_WRITE_AND_CLOSE 0x2C
#define SMB_COM_OPEN_ANDX 0x2D
#define SMB_COM_READ_ANDX 0x2E
#define SMB_COM_WRITE_ANDX 0x2F
#define SMB_COM_NEW_FILE_SIZE 0x30
#define SMB_COM_CLOSE_AND_TREE_DISC 0x31
#define SMB_COM_TRANSACTION2 0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_FIND_CLOSE2 0x34
#define SMB_COM_FIND_NOTIFY_CLOSE 0x35
#define SMB_COM_TREE_CONNECT 0x70
#define SMB_COM_TREE_DISCONNECT 0x71
#define SMB_COM_NEGOTIATE 0x72
#define SMB_COM_SESSION_SETUP_ANDX 0x73
#define SMB_COM_LOGOFF_ANDX 0x74
#define SMB_COM_TREE_CONNECT_ANDX 0x75
#define SMB_COM_SECURITY_PACKAGE_ANDX 0x7E
#define SMB_COM_QUERY_INFORMATION_DISK 0x80
#define SMB_COM_SEARCH 0x81
#define SMB_COM_FIND 0x82
#define SMB_COM_FIND_UNIQUE 0x83
#define SMB_COM_FIND_CLOSE 0x84
#define SMB_COM_NT_TRANSACT 0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1
#define SMB_COM_NT_CREATE_ANDX 0xA2
#define SMB_COM_NT_CANCEL 0xA4
#define SMB_COM_NT_RENAME 0xA5
#define SMB_COM_OPEN_PRINT_FILE 0xC0
#define SMB_COM_WRITE_PRINT_FILE 0xC1
#define SMB_COM_CLOSE_PRINT_FILE 0xC2
#define SMB_COM_GET_PRINT_QUEUE 0xC3
#define SMB_COM_READ_BULK 0xD8
#define SMB_COM_WRITE_BULK 0xD9
#define SMB_COM_WRITE_BULK_DATA 0xDA
#define SMB_COM_INVALID 0xFE
#define SMB_COM_NO_ANDX_COMMAND 0xFF

/* Size of word count field + Word count * 2 bytes + Size of byte count field */
#define SMB_COM_SIZE(wct)  (sizeof(uint8_t) + ((wct) * sizeof(uint16_t)) + sizeof(uint16_t))

#define SMB_FLG__TYPE  0x80
#define SMB_TYPE__REQUEST   0
#define SMB_TYPE__RESPONSE  1

#define SMB_FLG2__UNICODE      0x8000
#define SMB_FLG2__NT_CODES     0x4000

#define SMB_NT_STATUS_SEVERITY__SUCCESS        0
#define SMB_NT_STATUS_SEVERITY__INFORMATIONAL  1
#define SMB_NT_STATUS_SEVERITY__WARNING        2
#define SMB_NT_STATUS_SEVERITY__ERROR          3

#define SMB_NT_STATUS__SUCCESS                0x00000000
#define SMB_NT_STATUS__INVALID_DEVICE_REQUEST 0xc0000010
#define SMB_NT_STATUS__RANGE_NOT_LOCKED       0xc000007e
#define SMB_NT_STATUS__PIPE_BROKEN            0xc000014b
#define SMB_NT_STATUS__PIPE_DISCONNECTED      0xc00000b0

#define SMB_ERROR_CLASS__SUCCESS  0x00
#define SMB_ERROR_CLASS__ERRDOS   0x01
#define SMB_ERROR_CLASS__ERRSRV   0x02
#define SMB_ERROR_CLASS__ERRHRD   0x03
#define SMB_ERROR_CLASS__ERRXOS   0x04
#define SMB_ERROR_CLASS__ERRMX1   0xe1
#define SMB_ERROR_CLASS__ERRMX2   0xe2
#define SMB_ERROR_CLASS__ERRMX3   0xe3
#define SMB_ERROR_CLASS__ERRCMD   0xff

#define SMB_ERRSRV__INVALID_DEVICE      0x0007
#define SMB_ERRDOS__NOT_LOCKED          0x009e
#define SMB_ERRDOS__BAD_PIPE            0x00e6
#define SMB_ERRDOS__PIPE_NOT_CONNECTED  0x00e9
#define SMB_ERRDOS__MORE_DATA           0x00ea

enum SmbTransactionSubcommand
{
    TRANS_UNKNOWN_0000             = 0x0000,
    TRANS_SET_NMPIPE_STATE         = 0x0001,
    TRANS_UNKNOWN_0002             = 0x0002,
    TRANS_UNKNOWN_0003             = 0x0003,
    TRANS_UNKNOWN_0004             = 0x0004,
    TRANS_UNKNOWN_0005             = 0x0005,
    TRANS_UNKNOWN_0006             = 0x0006,
    TRANS_UNKNOWN_0007             = 0x0007,
    TRANS_UNKNOWN_0008             = 0x0008,
    TRANS_UNKNOWN_0009             = 0x0009,
    TRANS_UNKNOWN_000A             = 0x000A,
    TRANS_UNKNOWN_000B             = 0x000B,
    TRANS_UNKNOWN_000C             = 0x000C,
    TRANS_UNKNOWN_000D             = 0x000D,
    TRANS_UNKNOWN_000E             = 0x000E,
    TRANS_UNKNOWN_000F             = 0x000F,
    TRANS_UNKNOWN_0010             = 0x0010,
    TRANS_RAW_READ_NMPIPE          = 0x0011,
    TRANS_UNKNOWN_0012             = 0x0012,
    TRANS_UNKNOWN_0013             = 0x0013,
    TRANS_UNKNOWN_0014             = 0x0014,
    TRANS_UNKNOWN_0015             = 0x0015,
    TRANS_UNKNOWN_0016             = 0x0016,
    TRANS_UNKNOWN_0017             = 0x0017,
    TRANS_UNKNOWN_0018             = 0x0018,
    TRANS_UNKNOWN_0019             = 0x0019,
    TRANS_UNKNOWN_001A             = 0x001A,
    TRANS_UNKNOWN_001B             = 0x001B,
    TRANS_UNKNOWN_001C             = 0x001C,
    TRANS_UNKNOWN_001D             = 0x001D,
    TRANS_UNKNOWN_001E             = 0x001E,
    TRANS_UNKNOWN_001F             = 0x001F,
    TRANS_UNKNOWN_0020             = 0x0020,
    TRANS_QUERY_NMPIPE_STATE       = 0x0021,
    TRANS_QUERY_NMPIPE_INFO        = 0x0022,
    TRANS_PEEK_NMPIPE              = 0x0023,
    TRANS_UNKNOWN_0024             = 0x0024,
    TRANS_UNKNOWN_0025             = 0x0025,
    TRANS_TRANSACT_NMPIPE          = 0x0026,
    TRANS_UNKNOWN_0027             = 0x0027,
    TRANS_UNKNOWN_0028             = 0x0028,
    TRANS_UNKNOWN_0029             = 0x0029,
    TRANS_UNKNOWN_002A             = 0x002A,
    TRANS_UNKNOWN_002B             = 0x002B,
    TRANS_UNKNOWN_002C             = 0x002C,
    TRANS_UNKNOWN_002D             = 0x002D,
    TRANS_UNKNOWN_002E             = 0x002E,
    TRANS_UNKNOWN_002F             = 0x002F,
    TRANS_UNKNOWN_0030             = 0x0030,
    TRANS_RAW_WRITE_NMPIPE         = 0x0031,
    TRANS_UNKNOWN_0032             = 0x0032,
    TRANS_UNKNOWN_0033             = 0x0033,
    TRANS_UNKNOWN_0034             = 0x0034,
    TRANS_UNKNOWN_0035             = 0x0035,
    TRANS_READ_NMPIPE              = 0x0036,
    TRANS_WRITE_NMPIPE             = 0x0037,
    TRANS_UNKNOWN_0038             = 0x0038,
    TRANS_UNKNOWN_0039             = 0x0039,
    TRANS_UNKNOWN_003A             = 0x003A,
    TRANS_UNKNOWN_003B             = 0x003B,
    TRANS_UNKNOWN_003C             = 0x003C,
    TRANS_UNKNOWN_003D             = 0x003D,
    TRANS_UNKNOWN_003E             = 0x003E,
    TRANS_UNKNOWN_003F             = 0x003F,
    TRANS_UNKNOWN_0040             = 0x0040,
    TRANS_UNKNOWN_0041             = 0x0041,
    TRANS_UNKNOWN_0042             = 0x0042,
    TRANS_UNKNOWN_0043             = 0x0043,
    TRANS_UNKNOWN_0044             = 0x0044,
    TRANS_UNKNOWN_0045             = 0x0045,
    TRANS_UNKNOWN_0046             = 0x0046,
    TRANS_UNKNOWN_0047             = 0x0047,
    TRANS_UNKNOWN_0048             = 0x0048,
    TRANS_UNKNOWN_0049             = 0x0049,
    TRANS_UNKNOWN_004A             = 0x004A,
    TRANS_UNKNOWN_004B             = 0x004B,
    TRANS_UNKNOWN_004C             = 0x004C,
    TRANS_UNKNOWN_004D             = 0x004D,
    TRANS_UNKNOWN_004E             = 0x004E,
    TRANS_UNKNOWN_004F             = 0x004F,
    TRANS_UNKNOWN_0050             = 0x0050,
    TRANS_UNKNOWN_0051             = 0x0051,
    TRANS_UNKNOWN_0052             = 0x0052,
    TRANS_WAIT_NMPIPE              = 0x0053,
    TRANS_CALL_NMPIPE              = 0x0054,
    TRANS_SUBCOM_MAX               = 0x0055
};

enum SmbTransaction2Subcommand
{
    TRANS2_OPEN2                        = 0x0000,
    TRANS2_FIND_FIRST2                  = 0x0001,
    TRANS2_FIND_NEXT2                   = 0x0002,
    TRANS2_QUERY_FS_INFORMATION         = 0x0003,
    TRANS2_SET_FS_INFORMATION           = 0x0004,
    TRANS2_QUERY_PATH_INFORMATION       = 0x0005,
    TRANS2_SET_PATH_INFORMATION         = 0x0006,
    TRANS2_QUERY_FILE_INFORMATION       = 0x0007,
    TRANS2_SET_FILE_INFORMATION         = 0x0008,
    TRANS2_FSCTL                        = 0x0009,
    TRANS2_IOCTL2                       = 0x000A,
    TRANS2_FIND_NOTIFY_FIRST            = 0x000B,
    TRANS2_FIND_NOTIFY_NEXT             = 0x000C,
    TRANS2_CREATE_DIRECTORY             = 0x000D,
    TRANS2_SESSION_SETUP                = 0x000E,
    TRANS2_UNKNOWN_000F                 = 0x000F,
    TRANS2_GET_DFS_REFERRAL             = 0x0010,
    TRANS2_REPORT_DFS_INCONSISTENCY     = 0x0011,
    TRANS2_SUBCOM_MAX                   = 0x0012
};

/********************************************************************
 * Structures and inline accessor functions
 ********************************************************************/
/* Pack the structs since we'll be laying them on top of packet data */
#pragma pack(1)

/********************************************************************
 * NetBIOS Session Service header
 ********************************************************************/
struct NbssHdr
{
    uint8_t type;
    uint8_t flags;   /* Treat flags as the upper byte to length */
    uint16_t length;
};

struct SmbNtHdr
{
    uint8_t smb_idf[4];             /* contains 0xFF, 'SMB' */
    uint8_t smb_com;                /* command code */
    union
    {
        struct
        {
            uint8_t smb_class;      /* dos error class */
            uint8_t smb_res;        /* reserved for future */
            uint16_t smb_code;      /* dos error code */
        } smb_status;
        uint32_t nt_status;         /* nt status */
    } smb_status;
    uint8_t smb_flg;                /* flags */
    uint16_t smb_flg2;              /* flags */
    uint16_t smb_pid_high;
    uint64_t smb_signature;
    uint16_t smb_res;               /* reserved for future */
    uint16_t smb_tid;               /* tree id */
    uint16_t smb_pid;               /* caller's process id */
    uint16_t smb_uid;               /* authenticated user id */
    uint16_t smb_mid;               /* multiplex id */
};

/* For server empty responses indicating client error or interim response */
struct SmbEmptyCom
{
    uint8_t smb_wct;     /* value = 0 */
    uint16_t smb_bcc;    /* value = 0 */
};

/********************************************************************
 * Common fields to all commands
 ********************************************************************/
struct SmbCommon
{
    uint8_t smb_wct;
};

inline uint8_t SmbWct(const SmbCommon* hdr)
{
    return hdr->smb_wct;
}

/* Common fields to all AndX commands */
struct SmbAndXCommon
{
    uint8_t smb_wct;
    uint8_t smb_com2;      /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;      /* reserved (must be zero) */
    uint16_t smb_off2;     /* offset (from SMB hdr start) to next cmd (@smb_wct) */
};

inline uint32_t NbssLen(const NbssHdr* nb)
{
    /* Treat first bit of flags as the upper byte to length */
    // The left operand of '&' is a garbage value
    return ((nb->flags & 0x01) << 16) | ntohs(nb->length);  // ... FIXIT-W
}

inline uint8_t NbssType(const NbssHdr* nb)
{
    return nb->type;
}

inline uint32_t SmbId(const SmbNtHdr* hdr)
{
    const uint8_t* idf = (const uint8_t*)hdr->smb_idf;
    return *idf << 24 | *(idf + 1) << 16 | *(idf + 2) << 8 | *(idf + 3);
}

inline uint8_t SmbEmptyComWct(const SmbEmptyCom* ec)
{
    return ec->smb_wct;
}

inline uint16_t SmbBcc(const uint8_t* ptr, uint16_t com_size)
{
    /* com_size must be at least the size of the command encasing */
    if (com_size < sizeof(SmbEmptyCom))
        return 0;

    return snort::alignedNtohs((const uint16_t*)(ptr + com_size - sizeof(uint16_t)));
}

inline uint16_t SmbEmptyComBcc(const SmbEmptyCom* ec)
{
    return snort::alignedNtohs(&ec->smb_bcc);
}

inline int SmbType(const SmbNtHdr* hdr)
{
    // Access to field 'smb_flg' results in a dereference of a null pointer
    // (loaded from variable 'hdr')
    if (hdr->smb_flg & SMB_FLG__TYPE)  // ... FIXIT-W
        return SMB_TYPE__RESPONSE;

    return SMB_TYPE__REQUEST;
}

inline uint8_t SmbAndXCom2(const SmbAndXCommon* andx)
{
    return andx->smb_com2;
}

inline uint16_t SmbAndXOff2(const SmbAndXCommon* andx)
{
    return snort::alignedNtohs(&andx->smb_off2);
}

/* SMB formats (smb_fmt) Dialect, Pathname and ASCII are all
 * NULL terminated ASCII strings unless Unicode is specified
 * in the NT LM 1.0 SMB header in which case they are NULL
 * terminated unicode strings
 */
#define SMB_FMT__DATA_BLOCK  1
#define SMB_FMT__DIALECT     2
#define SMB_FMT__ASCII       4

inline bool SmbFmtDataBlock(const uint8_t fmt)
{
    return fmt == SMB_FMT__DATA_BLOCK ? true : false;
}

inline bool SmbFmtDialect(const uint8_t fmt)
{
    return fmt == SMB_FMT__DIALECT ? true : false;
}

inline bool SmbFmtAscii(const uint8_t fmt)
{
    return fmt == SMB_FMT__ASCII ? true : false;
}

#endif

