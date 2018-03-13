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

// smb_message.h author Russ Combs <rucombs@cisco.com>

// extracted from dce_smb.h originally written by Todd Wease

#ifndef SMB_MESSAGE_H
#define SMB_MESSAGE_H

#include <cstdint>

namespace snort
{
struct Packet;
}

/********************************************************************
 * SMB_COM_OPEN
 ********************************************************************/
struct SmbOpenReq   /* smb_wct = 2 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_mode;    /* r/w/share */
    uint16_t smb_attr;    /* attribute */
    uint16_t smb_bcc;     /* min = 2 */
};

struct SmbOpenResp   /* smb_wct = 7 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_attr;    /* attribute */
    uint32_t smb_time;    /* time1 low */
    uint32_t smb_file_size;   /* file size low */
    uint16_t smb_access;  /* access allowed */
    uint16_t smb_bcc;     /* must be 0 */
};

#define SMB_OPEN_ACCESS_MODE__READ        0x0000
#define SMB_OPEN_ACCESS_MODE__WRITE       0x0001
#define SMB_OPEN_ACCESS_MODE__READ_WRITE  0x0002
#define SMB_OPEN_ACCESS_MODE__EXECUTE     0x0003

inline uint16_t SmbOpenRespFid(const SmbOpenResp* resp)
{
    return snort::alignedNtohs(&resp->smb_fid);
}

inline uint32_t SmbOpenRespFileSize(const SmbOpenResp* resp)
{
    return snort::alignedNtohl(&resp->smb_file_size);
}

inline uint16_t SmbOpenRespFileAttrs(const SmbOpenResp* resp)
{
    return snort::alignedNtohs(&resp->smb_attr);
}

inline bool SmbFileAttrsDirectory(const uint16_t file_attrs)
{
    if (file_attrs & SMB_FILE_ATTRIBUTE_DIRECTORY)
        return true;
    return false;
}

inline uint16_t SmbOpenRespAccessMode(const SmbOpenResp* resp)
{
    return snort::alignedNtohs(&resp->smb_access);
}

inline bool SmbOpenForWriting(const uint16_t access_mode)
{
    return access_mode == SMB_OPEN_ACCESS_MODE__WRITE;
}

/********************************************************************
 * SMB_COM_CREATE
 ********************************************************************/
struct SmbCreateReq   /* smb_wct = 3 */
{
    uint8_t smb_wct;
    uint16_t smb_file_attrs;
    uint32_t smb_creation_time;
    uint16_t smb_bcc;
};

struct SmbCreateResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;
    uint16_t smb_fid;
    uint16_t smb_bcc;
};

inline uint16_t SmbCreateReqFileAttrs(const SmbCreateReq* req)
{
    return snort::alignedNtohs(&req->smb_file_attrs);
}

inline bool SmbAttrDirectory(const uint16_t file_attrs)
{
    if (file_attrs & SMB_FILE_ATTRIBUTE_DIRECTORY)
        return true;
    return false;
}

inline uint16_t SmbCreateRespFid(const SmbCreateResp* resp)
{
    return snort::alignedNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_CLOSE
 ********************************************************************/
struct SmbCloseReq   /* smb_wct = 3 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_tlow;    /* time low */
    uint16_t smb_thigh;   /* time high */
    uint16_t smb_bcc;     /* must be 0 */
};

struct SmbCloseResp   /* smb_wct = 0 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_bcc;     /* must be 0 */
};

inline uint16_t SmbCloseReqFid(const SmbCloseReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

/********************************************************************
 * SMB_COM_DELETE
 ********************************************************************/
struct SmbDeleteReq  /* smb_wct = 1 */
{
    uint8_t  smb_wct;
    uint16_t smb_search_attrs;
    uint16_t smb_bcc;
};

/********************************************************************
 * SMB_COM_READ
 ********************************************************************/
struct SmbReadReq   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_cnt;     /* count of bytes */
    uint32_t smb_off;     /* offset */
    uint16_t smb_left;    /* count left */
    uint16_t smb_bcc;     /* must be 0 */
};

struct SmbReadResp   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_res[4];  /* reserved (MBZ) */
    uint16_t smb_bcc;     /* length of data + 3 */
};

inline uint16_t SmbReadReqFid(const SmbReadReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint32_t SmbReadReqOffset(const SmbReadReq* req)
{
    return snort::alignedNtohl(&req->smb_off);
}

inline uint16_t SmbReadRespCount(const SmbReadResp* resp)
{
    return snort::alignedNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_WRITE
 ********************************************************************/
struct SmbWriteReq   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_cnt;     /* count of bytes */
    uint32_t smb_offset;  /* file offset in bytes */
    uint16_t smb_left;    /* count left */
    uint16_t smb_bcc;     /* length of data + 3 */
};

struct SmbWriteResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_bcc;     /* must be 0 */
};

inline uint16_t SmbWriteReqFid(const SmbWriteReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteReqCount(const SmbWriteReq* req)
{
    return snort::alignedNtohs(&req->smb_cnt);
}

inline uint32_t SmbWriteReqOffset(const SmbWriteReq* req)
{
    return snort::alignedNtohl(&req->smb_offset);
}

inline uint16_t SmbWriteRespCount(const SmbWriteResp* resp)
{
    return snort::alignedNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_CREATE_NEW
 ********************************************************************/
struct SmbCreateNewReq   /* smb_wct = 3 */
{
    uint8_t smb_wct;
    uint16_t smb_file_attrs;
    uint32_t smb_creation_time;
    uint16_t smb_bcc;
};

struct SmbCreateNewResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;
    uint16_t smb_fid;
    uint16_t smb_bcc;
};

inline uint16_t SmbCreateNewReqFileAttrs(const SmbCreateNewReq* req)
{
    return snort::alignedNtohs(&req->smb_file_attrs);
}

inline uint16_t SmbCreateNewRespFid(const SmbCreateNewResp* resp)
{
    return snort::alignedNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_LOCK_AND_READ
 ********************************************************************/
struct SmbLockAndReadReq   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;
    uint16_t smb_cnt;
    uint32_t smb_read_offset;
    uint16_t smb_remaining;
    uint16_t smb_bcc;     /* must be 0 */
};

struct SmbLockAndReadResp   /* smb_wct = 5 */
{
    uint8_t smb_wct;
    uint16_t smb_cnt;
    uint16_t reserved[4];
    uint16_t smb_bcc;
};

inline uint16_t SmbLockAndReadReqFid(const SmbLockAndReadReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint32_t SmbLockAndReadReqOffset(const SmbLockAndReadReq* req)
{
    return snort::alignedNtohl(&req->smb_read_offset);
}

inline uint16_t SmbLockAndReadRespCount(const SmbLockAndReadResp* resp)
{
    return snort::alignedNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_WRITE_AND_UNLOCK
 ********************************************************************/
struct SmbWriteAndUnlockReq
{
    uint8_t smb_wct;
    uint16_t smb_fid;
    uint16_t smb_cnt;
    uint32_t smb_write_offset;
    uint16_t smb_estimate_of_remaining;
    uint16_t smb_bcc;
};

struct SmbWriteAndUnlockResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_bcc;     /* must be 0 */
};

inline uint16_t SmbWriteAndUnlockReqFid(const SmbWriteAndUnlockReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteAndUnlockReqCount(const SmbWriteAndUnlockReq* req)
{
    return snort::alignedNtohs(&req->smb_cnt);
}

inline uint32_t SmbWriteAndUnlockReqOffset(const SmbWriteAndUnlockReq* req)
{
    return snort::alignedNtohl(&req->smb_write_offset);
}

/********************************************************************
 * SMB_COM_OPEN_ANDX
 ********************************************************************/
struct SmbOpenAndXReq   /* smb_wct = 15 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_flags;      /* additional information:
                                bit 0 - if set, return additional information
                                bit 1 - if set, set single user total file lock (if only access)
                                bit 2 - if set, the server should notify the consumer on any
                                        action which can modify the file (delete, setattrib,
                                        rename, etc.). if not set, the server need only notify
                                        the consumer on another open request. This bit only has
                                        meaning if bit 1 is set. */
    uint16_t smb_mode;       /* file open mode */
    uint16_t smb_sattr;      /* search attributes */
    uint16_t smb_attr;       /* file attributes (for create) */
    uint32_t smb_time;       /* create time */
    uint16_t smb_ofun;       /* open function */
    uint32_t smb_size;       /* bytes to reserve on "create" or "truncate" */
    uint32_t smb_timeout;    /* max milliseconds to wait for resource to open */
    uint32_t smb_rsvd;       /* reserved (must be zero) */
    uint16_t smb_bcc;        /* minimum value = 1 */
};

struct SmbOpenAndXResp   /* smb_wct = 15 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;        /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint16_t smb_attribute;  /* attributes of file or device */
    uint32_t smb_time;       /* last modification time */
    uint32_t smb_size;       /* current file size */
    uint16_t smb_access;     /* access permissions actually allowed */
    uint16_t smb_type;       /* file type */
    uint16_t smb_state;      /* state of IPC device (e.g. pipe) */
    uint16_t smb_action;     /* action taken */
    uint32_t smb_fileid;     /* server unique file id */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */
};

inline uint32_t SmbOpenAndXReqAllocSize(const SmbOpenAndXReq* req)
{
    return snort::alignedNtohl(&req->smb_size);
}

inline uint16_t SmbOpenAndXReqFileAttrs(const SmbOpenAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_attr);
}

inline uint16_t SmbOpenAndXRespFid(const SmbOpenAndXResp* resp)
{
    return snort::alignedNtohs(&resp->smb_fid);
}

inline uint16_t SmbOpenAndXRespFileAttrs(const SmbOpenAndXResp* resp)
{
    return snort::alignedNtohs(&resp->smb_attribute);
}

inline uint32_t SmbOpenAndXRespFileSize(const SmbOpenAndXResp* resp)
{
    return snort::alignedNtohl(&resp->smb_size);
}

inline uint16_t SmbOpenAndXRespResourceType(const SmbOpenAndXResp* resp)
{
    return snort::alignedNtohs(&resp->smb_type);
}

#define SMB_OPEN_RESULT__EXISTED    0x0001
#define SMB_OPEN_RESULT__CREATED    0x0002
#define SMB_OPEN_RESULT__TRUNCATED  0x0003

inline uint16_t SmbOpenAndXRespOpenResults(const SmbOpenAndXResp* resp)
{
    return snort::alignedNtohs(&resp->smb_action);
}

inline bool SmbOpenResultRead(const uint16_t open_results)
{
    return ((open_results & 0x00FF) == SMB_OPEN_RESULT__EXISTED);
}

inline bool SmbResourceTypeDisk(const uint16_t resource_type)
{
    return resource_type == SMB_FILE_TYPE_DISK;
}

/********************************************************************
 * SMB_COM_READ_ANDX
 ********************************************************************/
struct SmbReadAndXReq   /* smb_wct = 10 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return */
    uint16_t smb_mincnt;     /* min number of bytes to return */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_countleft;  /* bytes remaining to satisfy user’s request */
    uint16_t smb_bcc;        /* value = 0 */
};

struct SmbReadAndXExtReq   /* smb_wct = 12 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* low offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return */
    uint16_t smb_mincnt;     /* min number of bytes to return */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_countleft;  /* bytes remaining to satisfy user’s request */
    uint32_t smb_off_high;   /* high offset in file to begin read */
    uint16_t smb_bcc;        /* value = 0 */
};

struct SmbReadAndXResp    /* smb_wct = 12 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;        /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint32_t smb_rsvd;       /* reserved */
    uint16_t smb_dsize;      /* number of data bytes (minimum value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_dsize_high; /* high bytes of data size */
    uint32_t smb_rsvd1;      /* reserved */
    uint32_t smb_rsvd2;      /* reserved */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
};

inline uint16_t SmbReadAndXReqFid(const SmbReadAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint64_t SmbReadAndXReqOffset(const SmbReadAndXExtReq* req)
{
    if (req->smb_wct == 10)
        return (uint64_t)snort::alignedNtohl(&req->smb_offset);

    return (uint64_t)snort::alignedNtohl(&req->smb_off_high) << 32
                    | (uint64_t)snort::alignedNtohl(&req->smb_offset);
}

inline uint16_t SmbReadAndXRespDataOff(const SmbReadAndXResp* req)
{
    return snort::alignedNtohs(&req->smb_doff);
}

inline uint32_t SmbReadAndXRespDataCnt(const SmbReadAndXResp* resp)
{
    return (uint32_t)snort::alignedNtohs(&resp->smb_dsize_high) << 16
                    | (uint32_t)snort::alignedNtohs(&resp->smb_dsize);
}

/********************************************************************
 * SMB_COM_WRITE_ANDX
 ********************************************************************/
struct SmbWriteAndXReq   /* smb_wct = 12 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin write */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;      /* write mode:
                                bit0 - complete write before return (write through)
                                bit1 - return smb_remaining (pipes/devices only)
                                bit2 - use WriteRawNamedPipe (pipes only)
                                bit3 - this is the start of a message (pipes only) */
    uint16_t smb_countleft;  /* bytes remaining to write to satisfy user’s request */
    uint16_t smb_dsize_high; /* high bytes of data size */
    uint16_t smb_dsize;      /* number of data bytes in buffer (min value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
};

struct SmbWriteAndXExtReq   /* smb_wct = 14 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* low offset in file to begin write */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;      /* write mode:
                                bit0 - complete write before return (write through)
                                bit1 - return smb_remaining (pipes/devices only)
                                bit2 - use WriteRawNamedPipe (pipes only)
                                bit3 - this is the start of a message (pipes only) */
    uint16_t smb_countleft;  /* bytes remaining to write to satisfy user’s request */
    uint16_t smb_dsize_high; /* high bytes of data size */
    uint16_t smb_dsize;      /* number of data bytes in buffer (min value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint32_t smb_off_high;   /* high offset in file to begin write */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
};

struct SmbWriteAndXResp   /* smb_wct = 6 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;        /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_count;      /* number of bytes written */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint16_t smb_count_high; /* high order bytes of data count */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */
};

inline uint16_t SmbWriteAndXReqFid(const SmbWriteAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteAndXReqDataOff(const SmbWriteAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_doff);
}

inline uint16_t SmbWriteAndXReqRemaining(const SmbWriteAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_countleft);
}

inline uint64_t SmbWriteAndXReqOffset(const SmbWriteAndXExtReq* req)
{
    if (req->smb_wct == 12)
        return (uint64_t)snort::alignedNtohl(&req->smb_offset);

    return (uint64_t)snort::alignedNtohl(&req->smb_off_high) << 32
                    | (uint64_t)snort::alignedNtohl(&req->smb_offset);
}

inline uint32_t SmbWriteAndXReqDataCnt(const SmbWriteAndXReq* req)
{
    return (uint32_t)snort::alignedNtohs(&req->smb_dsize_high) << 16
                    | (uint32_t)snort::alignedNtohs(&req->smb_dsize);
}

inline uint16_t SmbWriteAndXReqWriteMode(const SmbWriteAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_wmode);
}

inline bool SmbWriteAndXReqStartRaw(const SmbWriteAndXReq* req)
{
    return ((snort::alignedNtohs(&req->smb_wmode) & 0x000c) == 0x000c) ? true : false;
}

inline bool SmbWriteAndXReqRaw(const SmbWriteAndXReq* req)
{
    return ((snort::alignedNtohs(&req->smb_wmode) & 0x000c) == 0x0004) ? true : false;
}

inline uint16_t SmbWriteAndXRespCnt(const SmbWriteAndXResp* resp)
{
    return snort::alignedNtohs(&resp->smb_count);
}

/********************************************************************
 * SMB_COM_SESSION_SETUP_ANDX
 ********************************************************************/
struct SmbLm10_SessionSetupAndXReq   /* smb_wct = 10 */
{
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint8_t smb_com2;      /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;      /* reserved (must be zero) */
    uint16_t smb_off2;     /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;  /* the consumers max buffer size */
    uint16_t smb_mpxmax;   /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;   /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;  /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_apasslen; /* size of account password (smb_apasswd) */
    uint32_t smb_rsvd;     /* reserved */
    uint16_t smb_bcc;      /* minimum value = 0 */
};

inline uint16_t SmbSessionSetupAndXReqMaxMultiplex(const SmbLm10_SessionSetupAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_mpxmax);
}

/* Extended request as defined in NT LM 1.0 document */
struct SmbNt10_SessionSetupAndXReq   /* smb_wct = 13 */
{
    uint8_t smb_wct;              /* count of 16-bit words that follow */
    uint8_t smb_com2;             /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;             /* reserved (must be zero) */
    uint16_t smb_off2;            /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;         /* the consumers max buffer size */
    uint16_t smb_mpxmax;          /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;          /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;         /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_oem_passlen;     /* case insensitive password length */
    uint16_t smb_unicode_passlen; /* case sensitive password length */
    uint32_t smb_rsvd;            /* reserved */
    uint32_t smb_cap;             /* capabilities */
    uint16_t smb_bcc;             /* minimum value = 0 */
};

inline uint16_t SmbNt10SessionSetupAndXReqOemPassLen(const SmbNt10_SessionSetupAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_oem_passlen);
}

inline uint16_t SmbNt10SessionSetupAndXReqUnicodePassLen(const SmbNt10_SessionSetupAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_unicode_passlen);
}

/* Extended request for security blob */
struct SmbNt10_SessionSetupAndXExtReq   /* smb_wct = 12 */
{
    uint8_t smb_wct;          /* count of 16-bit words that follow */
    uint8_t smb_com2;         /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;         /* reserved (must be zero) */
    uint16_t smb_off2;        /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;     /* the consumers max buffer size */
    uint16_t smb_mpxmax;      /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;      /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;     /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_blob_len;    /* length of security blob */
    uint32_t smb_rsvd;        /* reserved */
    uint32_t smb_cap;         /* capabilities */
    uint16_t smb_bcc;         /* minimum value = 0 */
};

inline uint16_t SmbSessionSetupAndXReqBlobLen(const SmbNt10_SessionSetupAndXExtReq* req)
{
    return snort::alignedNtohs(&req->smb_blob_len);
}

/* Extended response for security blob */
struct SmbNt10_SessionSetupAndXExtResp   /* smb_wct = 4 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;        /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_action;     /* request mode:
                                bit0 = Logged in successfully - BUT as GUEST */
    uint16_t smb_blob_len;   /* length of security blob */
    uint16_t smb_bcc;        /* min value = 0 */
};

inline uint16_t SmbSessionSetupAndXRespBlobLen(const SmbNt10_SessionSetupAndXExtResp* resp)
{
    return snort::alignedNtohs(&resp->smb_blob_len);
}

/********************************************************************
 * SMB_COM_NEGOTIATE
 ********************************************************************/
/* This is the Lanman response */
struct SmbLm10_NegotiateProtocolResp   /* smb_wct = 13 */
{
    uint8_t smb_wct;        /* count of 16-bit words that follow */
    uint16_t smb_index;     /* index identifying dialect selected */
    uint16_t smb_secmode;   /* security mode:
                               bit 0, 1 = User level, 0 = Share level
                               bit 1, 1 = encrypt passwords, 0 = do not encrypt passwords */
    uint16_t smb_maxxmt;    /* max transmit buffer size server supports, 1K min */
    uint16_t smb_maxmux;    /* max pending multiplexed requests server supports */
    uint16_t smb_maxvcs;    /* max VCs per server/consumer session supported */
    uint16_t smb_blkmode;   /* block read/write mode support:
                               bit 0, Read Block Raw supported (65535 bytes max)
                               bit 1, Write Block Raw supported (65535 bytes max) */
    uint32_t smb_sesskey;   /* Session Key (unique token identifying session) */
    uint16_t smb_srv_time;  /* server's current time (hhhhh mmmmmm xxxxx) */
    uint16_t smb_srv_tzone; /* server's current data (yyyyyyy mmmm ddddd) */
    uint32_t smb_rsvd;      /* reserved */
    uint16_t smb_bcc;       /* value = (size of smb_cryptkey) */
};

/* This is the NT response */
struct SmbNt_NegotiateProtocolResp     /* smb_wct = 17 */
{
    uint8_t smb_wct;            /* count of 16-bit words that follow */
    uint16_t smb_index;         /* index identifying dialect selected */
    uint8_t smb_secmode;        /* security mode:
                                   bit 0, 1 = User level, 0 = Share level
                                   bit 1, 1 = encrypt passwords, 0 = do not encrypt passwords */
    uint16_t smb_maxmux;        /* max pending multiplexed requests server supports */
    uint16_t smb_maxvcs;        /* max VCs per server/consumer session supported */
    uint32_t smb_maxbuf;        /* maximum buffer size supported */
    uint32_t smb_maxraw;        /* maximum raw buffer size supported */
    uint32_t smb_sesskey;       /* Session Key (unique token identifying session) */
    uint32_t smb_cap;           /* capabilities */
    struct
    {
        uint32_t low_time;
        int32_t high_time;
    } smb_srv_time;             /* server time */
    uint16_t smb_srv_tzone;     /* server's current data (yyyyyyy mmmm ddddd) */
    uint8_t smb_challenge_len;  /* Challenge length */
    uint16_t smb_bcc;           /* value = (size of smb_cryptkey) */
};

inline uint16_t SmbLm_NegotiateRespMaxMultiplex(const SmbLm10_NegotiateProtocolResp* resp)
{
    return snort::alignedNtohs(&resp->smb_maxmux);
}

inline uint16_t SmbNt_NegotiateRespMaxMultiplex(const SmbNt_NegotiateProtocolResp* resp)
{
    return snort::alignedNtohs(&resp->smb_maxmux);
}

/* This is the Core Protocol response */
struct SmbCore_NegotiateProtocolResp    /* smb_wct = 1 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_index;   /* index */
    uint16_t smb_bcc;     /* must be 0 */
};

inline uint16_t SmbNegotiateRespDialectIndex(const SmbCore_NegotiateProtocolResp* resp)
{
    return snort::alignedNtohs(&resp->smb_index);
}

/*********************************************************************
 * SMB_COM_TREE_CONNECT_ANDX
 *********************************************************************/
struct SmbTreeConnectAndXReq   /* smb_wct = 4 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_flags;      /* additional information:
                                bit 0 - if set, disconnect TID in current smb_tid */
    uint16_t smb_spasslen;   /* length of smb_spasswd */
    uint16_t smb_bcc;        /* minimum value = 3 */
};

inline uint16_t SmbTreeConnectAndXReqPassLen(const SmbTreeConnectAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_spasslen);
}

/********************************************************************
 * SMB_COM_NT_TRANSACT
 ********************************************************************/
#define SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY     0x00000004

/********************************************************************
 * SMB_COM_NT_CREATE_ANDX
 ********************************************************************/
#define SMB_CREATE_DISPOSITSION__FILE_SUPERCEDE      0x00000000
#define SMB_CREATE_DISPOSITSION__FILE_OPEN           0x00000001
#define SMB_CREATE_DISPOSITSION__FILE_CREATE         0x00000002
#define SMB_CREATE_DISPOSITSION__FILE_OPEN_IF        0x00000003
#define SMB_CREATE_DISPOSITSION__FILE_OVERWRITE      0x00000004
#define SMB_CREATE_DISPOSITSION__FILE_OVERWRITE_IF   0x00000005

struct SmbNtCreateAndXReq   /* smb_wct = 24 */
{
    uint8_t smb_wct;            /* count of 16-bit words that follow */
    uint8_t smb_com2;           /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;           /* reserved (pad to word) */
    uint16_t smb_off2;          /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint8_t smb_res;            /* reserved */
    uint16_t smb_name_len;      /* length of name of file */
    uint32_t smb_flags;         /* flags */
    uint32_t smb_root_fid;      /* fid for previously opened directory */
    uint32_t smb_access;        /* specifies the type of file access */
    uint64_t smb_alloc_size;    /* initial allocation size of the file */
    uint32_t smb_file_attrs;    /* specifies the file attributes for the file */
    uint32_t smb_share_access;  /* the type of share access */
    uint32_t smb_create_disp;   /* actions to take if file does or does not exist */
    uint32_t smb_create_opts;   /* options used when creating or opening file */
    uint32_t smb_impersonation_level;  /* security impersonation level */
    uint8_t smb_security_flags;   /* security flags */
    uint16_t smb_bcc;           /* byte count */
};

struct SmbNtCreateAndXResp    /* smb_wct = 34 */
{
    uint8_t smb_wct;
    uint8_t smb_com2;
    uint8_t smb_res2;
    uint16_t smb_off2;
    uint8_t smb_oplock_level;
    uint16_t smb_fid;
    uint32_t smb_create_disposition;
    uint64_t smb_creation_time;
    uint64_t smb_last_access_time;
    uint64_t smb_last_write_time;
    uint64_t smb_change_time;
    uint32_t smb_file_attrs;
    uint64_t smb_alloc_size;
    uint64_t smb_eof;
    uint16_t smb_resource_type;
    uint16_t smb_nm_pipe_state;
    uint8_t smb_directory;
    uint16_t smb_bcc;
};

// Word count is always set to 42 though there are actually 50 words
struct SmbNtCreateAndXExtResp    /* smb_wct = 42 */
{
    uint8_t smb_wct;
    uint8_t smb_com2;
    uint8_t smb_res2;
    uint16_t smb_off2;
    uint8_t smb_oplock_level;
    uint16_t smb_fid;
    uint32_t smb_create_disposition;
    uint64_t smb_creation_time;
    uint64_t smb_last_access_time;
    uint64_t smb_last_write_time;
    uint64_t smb_change_time;
    uint32_t smb_file_attrs;
    uint64_t smb_alloc_size;
    uint64_t smb_eof;
    uint16_t smb_resource_type;
    uint16_t smb_nm_pipe_state;
    uint8_t smb_directory;
    uint8_t smb_volume_guid[16];
    uint64_t smb_fileid;
    uint32_t smb_max_access_rights;
    uint32_t smb_guest_access_rights;
    uint16_t smb_bcc;
};

inline uint16_t SmbNtCreateAndXReqFileNameLen(const SmbNtCreateAndXReq* req)
{
    return snort::alignedNtohs(&req->smb_name_len);
}

inline uint32_t SmbNtCreateAndXReqCreateDisposition(const SmbNtCreateAndXReq* req)
{
    return snort::alignedNtohl(&req->smb_create_disp);
}

inline bool SmbCreateDispositionRead(const uint32_t create_disposition)
{
    return (create_disposition == SMB_CREATE_DISPOSITSION__FILE_OPEN)
           || (create_disposition > SMB_CREATE_DISPOSITSION__FILE_OVERWRITE_IF);
}

inline uint64_t SmbNtCreateAndXReqAllocSize(const SmbNtCreateAndXReq* req)
{
    return snort::alignedNtohq(&req->smb_alloc_size);
}

inline bool SmbNtCreateAndXReqSequentialOnly(const SmbNtCreateAndXReq* req)
{
    return (snort::alignedNtohl(&req->smb_create_opts) & SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY);
}

inline uint32_t SmbNtCreateAndXReqFileAttrs(const SmbNtCreateAndXReq* req)
{
    return snort::alignedNtohl(&req->smb_file_attrs);
}

inline uint16_t SmbNtCreateAndXRespFid(const SmbNtCreateAndXResp* resp)
{
    return snort::alignedNtohs(&resp->smb_fid);
}

inline uint32_t SmbNtCreateAndXRespCreateDisposition(const SmbNtCreateAndXResp* resp)
{
    return snort::alignedNtohl(&resp->smb_create_disposition);
}

inline bool SmbNtCreateAndXRespDirectory(const SmbNtCreateAndXResp* resp)
{
    return (resp->smb_directory ? true : false);
}

inline uint16_t SmbNtCreateAndXRespResourceType(const SmbNtCreateAndXResp* resp)
{
    return snort::alignedNtohs(&resp->smb_resource_type);
}

inline uint64_t SmbNtCreateAndXRespEndOfFile(const SmbNtCreateAndXResp* resp)
{
    return snort::alignedNtohq(&resp->smb_eof);
}

/********************************************************************
 * SMB_COM_TRANSACTION
 ********************************************************************/
struct SmbTransactionReq   /* smb_wct = 14 + value of smb_suwcnt */
{
    /* Note all subcommands use a setup count of 2 */
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_tpscnt;   /* total number of parameter bytes being sent */
    uint16_t smb_tdscnt;   /* total number of data bytes being sent */
    uint16_t smb_mprcnt;   /* max number of parameter bytes to return */
    uint16_t smb_mdrcnt;   /* max number of data bytes to return */
    uint8_t smb_msrcnt;    /* max number of setup words to return */
    uint8_t smb_rsvd;      /* reserved (pad above to word) */
    uint16_t smb_flags;    /* additional information:
                              bit 0 - if set, also disconnect TID in smb_tid
                              bit 1 - if set, transaction is one way (no final response) */
    uint32_t smb_timeout;  /* number of milliseconds to wait for completion */
    uint16_t smb_rsvd1;    /* reserved */
    uint16_t smb_pscnt;    /* number of parameter bytes being sent this buffer */
    uint16_t smb_psoff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_dscnt;    /* number of data bytes being sent this buffer */
    uint16_t smb_dsoff;    /* offset (from start of SMB hdr) to data bytes */
    uint8_t smb_suwcnt;    /* set up word count */
    uint8_t smb_rsvd2;     /* reserved (pad above to word) */
    uint16_t smb_setup1;   /* function (see below)
                                TRANS_SET_NM_PIPE_STATE   = 0x0001
                                TRANS_RAW_READ_NMPIPE     = 0x0011
                                TRANS_QUERY_NMPIPE_STATE  = 0x0021
                                TRANS_QUERY_NMPIPE_INFO   = 0x0022
                                TRANS_PEEK_NMPIPE         = 0x0023
                                TRANS_TRANSACT_NMPIPE     = 0x0026
                                TRANS_RAW_WRITE_NMPIPE    = 0x0031
                                TRANS_READ_NMPIPE         = 0x0036
                                TRANS_WRITE_NMPIPE        = 0x0037
                                TRANS_WAIT_NMPIPE         = 0x0053
                                TRANS_CALL_NMPIPE         = 0x0054  */
    uint16_t smb_setup2;   /* FID (handle) of pipe (if needed), or priority */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

struct SmbTransactionInterimResp    /* smb_wct = 0 */
{
    uint8_t smb_wct;        /* count of 16-bit words that follow */
    uint16_t smb_bcc;       /* must be 0 */
};

struct SmbTransactionResp   /* smb_wct = 10 + value of smb_suwcnt */
{
    /* Note all subcommands use a setup count of 0 */
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_tprcnt;   /* total number of parameter bytes being returned */
    uint16_t smb_tdrcnt;   /* total number of data bytes being returned */
    uint16_t smb_rsvd;     /* reserved */
    uint16_t smb_prcnt;    /* number of parameter bytes being returned this buf */
    uint16_t smb_proff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_prdisp;   /* byte displacement for these parameter bytes */
    uint16_t smb_drcnt;    /* number of data bytes being returned this buffer */
    uint16_t smb_droff;    /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_drdisp;   /* byte displacement for these data bytes */
    uint8_t smb_suwcnt;    /* set up return word count */
    uint8_t smb_rsvd1;     /* reserved (pad above to word) */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

inline uint16_t SmbTransactionReqSubCom(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_setup1);
}

inline uint16_t SmbTransactionReqFid(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_setup2);
}

inline bool SmbTransactionReqDisconnectTid(const SmbTransactionReq* req)
{
    return (snort::alignedNtohs(&req->smb_flags) & 0x0001) ? true : false;
}

inline bool SmbTransactionReqOneWay(const SmbTransactionReq* req)
{
    return (snort::alignedNtohs(&req->smb_flags) & 0x0002) ? true : false;
}

inline uint8_t SmbTransactionReqSetupCnt(const SmbTransactionReq* req)
{
    return req->smb_suwcnt;
}

inline uint16_t SmbTransactionReqTotalDataCnt(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_tdscnt);
}

inline uint16_t SmbTransactionReqDataCnt(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_dscnt);
}

inline uint16_t SmbTransactionReqDataOff(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_dsoff);
}

inline uint16_t SmbTransactionReqTotalParamCnt(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_tpscnt);
}

inline uint16_t SmbTransactionReqParamCnt(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_pscnt);
}

inline uint16_t SmbTransactionReqParamOff(const SmbTransactionReq* req)
{
    return snort::alignedNtohs(&req->smb_psoff);
}

inline uint16_t SmbTransactionRespTotalDataCnt(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_tdrcnt);
}

inline uint16_t SmbTransactionRespDataCnt(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_drcnt);
}

inline uint16_t SmbTransactionRespDataOff(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_droff);
}

inline uint16_t SmbTransactionRespDataDisp(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_drdisp);
}

inline uint16_t SmbTransactionRespTotalParamCnt(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_tprcnt);
}

inline uint16_t SmbTransactionRespParamCnt(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_prcnt);
}

inline uint16_t SmbTransactionRespParamOff(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_proff);
}

inline uint16_t SmbTransactionRespParamDisp(const SmbTransactionResp* resp)
{
    return snort::alignedNtohs(&resp->smb_prdisp);
}

// Flags for TRANS_SET_NMPIPE_STATE parameters
#define PIPE_STATE_NON_BLOCKING  0x8000
#define PIPE_STATE_MESSAGE_MODE  0x0100

/********************************************************************
 * SMB_COM_TRANSACTION2
 ********************************************************************/
struct SmbTransaction2Req
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_max_param_count;
    uint16_t smb_max_data_count;
    uint8_t smb_max_setup_count;
    uint8_t smb_res;
    uint16_t smb_flags;
    uint32_t smb_timeout;
    uint16_t smb_res2;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint8_t smb_setup_count;    /* Should be 1 for all subcommands */
    uint8_t smb_res3;
    uint16_t smb_setup;  /* This is the subcommand */
    uint16_t smb_bcc;
};

struct SmbTransaction2InterimResp
{
    uint8_t smb_wct;
    uint16_t smb_bcc;
};

struct SmbTransaction2Resp
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 or 1 word */
    uint8_t smb_res2;
};

inline uint16_t SmbTransaction2ReqSubCom(const SmbTransaction2Req* req)
{
    return snort::alignedNtohs(&req->smb_setup);
}

inline uint16_t SmbTransaction2ReqTotalParamCnt(const SmbTransaction2Req* req)
{
    return snort::alignedNtohs(&req->smb_total_param_count);
}

inline uint16_t SmbTransaction2ReqParamCnt(const SmbTransaction2Req* req)
{
    return snort::alignedNtohs(&req->smb_param_count);
}

inline uint16_t SmbTransaction2ReqParamOff(const SmbTransaction2Req* req)
{
    return snort::alignedNtohs(&req->smb_param_offset);
}

inline uint16_t SmbTransaction2ReqTotalDataCnt(const SmbTransaction2Req* req)
{
    return snort::alignedNtohs(&req->smb_total_data_count);
}

inline uint16_t SmbTransaction2ReqDataCnt(const SmbTransaction2Req* req)
{
    return snort::alignedNtohs(&req->smb_data_count);
}

inline uint16_t SmbTransaction2ReqDataOff(const SmbTransaction2Req* req)
{
    return snort::alignedNtohs(&req->smb_data_offset);
}

inline uint8_t SmbTransaction2ReqSetupCnt(const SmbTransaction2Req* req)
{
    return req->smb_setup_count;
}

inline uint16_t SmbTransaction2RespTotalParamCnt(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_total_param_count);
}

inline uint16_t SmbTransaction2RespParamCnt(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_param_count);
}

inline uint16_t SmbTransaction2RespParamOff(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_param_offset);
}

inline uint16_t SmbTransaction2RespParamDisp(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_param_disp);
}

inline uint16_t SmbTransaction2RespTotalDataCnt(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_total_data_count);
}

inline uint16_t SmbTransaction2RespDataCnt(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_data_count);
}

inline uint16_t SmbTransaction2RespDataOff(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_data_offset);
}

inline uint16_t SmbTransaction2RespDataDisp(const SmbTransaction2Resp* resp)
{
    return snort::alignedNtohs(&resp->smb_data_disp);
}

struct SmbTrans2Open2ReqParams
{
    uint16_t Flags;
    uint16_t AccessMode;
    uint16_t Reserved1;
    uint16_t FileAttributes;
    uint32_t CreationTime;
    uint16_t OpenMode;
    uint32_t AllocationSize;
    uint16_t Reserved[5];
};

typedef SmbTransaction2Req SmbTrans2Open2Req;

inline uint16_t SmbTrans2Open2ReqAccessMode(const SmbTrans2Open2ReqParams* req)
{
    return snort::alignedNtohs(&req->AccessMode);
}

inline uint16_t SmbTrans2Open2ReqFileAttrs(const SmbTrans2Open2ReqParams* req)
{
    return snort::alignedNtohs(&req->FileAttributes);
}

inline uint16_t SmbTrans2Open2ReqOpenMode(const SmbTrans2Open2ReqParams* req)
{
    return snort::alignedNtohs(&req->OpenMode);
}

inline uint32_t SmbTrans2Open2ReqAllocSize(const SmbTrans2Open2ReqParams* req)
{
    return snort::alignedNtohl(&req->AllocationSize);
}

struct SmbTrans2Open2RespParams
{
    uint16_t smb_fid;
    uint16_t file_attributes;
    uint32_t creation_time;
    uint32_t file_data_size;
    uint16_t access_mode;
    uint16_t resource_type;
    uint16_t nm_pipe_status;
    uint16_t action_taken;
    uint32_t reserved;
    uint16_t extended_attribute_error_offset;
    uint32_t extended_attribute_length;
};

inline uint16_t SmbTrans2Open2RespFid(const SmbTrans2Open2RespParams* resp)
{
    return snort::alignedNtohs(&resp->smb_fid);
}

inline uint16_t SmbTrans2Open2RespFileAttrs(const SmbTrans2Open2RespParams* resp)
{
    return snort::alignedNtohs(&resp->file_attributes);
}

inline uint32_t SmbTrans2Open2RespFileDataSize(const SmbTrans2Open2RespParams* resp)
{
    return snort::alignedNtohl(&resp->file_data_size);
}

inline uint16_t SmbTrans2Open2RespResourceType(const SmbTrans2Open2RespParams* resp)
{
    return snort::alignedNtohs(&resp->resource_type);
}

inline uint16_t SmbTrans2Open2RespActionTaken(const SmbTrans2Open2RespParams* resp)
{
    return snort::alignedNtohs(&resp->action_taken);
}

struct SmbTrans2Open2Resp
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 */
    uint8_t smb_res2;
    uint16_t smb_bcc;
};

// See MS-CIFS Section 2.2.2.3.3
#define SMB_INFO_STANDARD               0x0001
#define SMB_INFO_QUERY_EA_SIZE          0x0002
#define SMB_INFO_QUERY_EAS_FROM_LIST    0x0003
#define SMB_INFO_QUERY_ALL_EAS          0x0004
#define SMB_INFO_IS_NAME_VALID          0x0006
#define SMB_QUERY_FILE_BASIC_INFO       0x0101
#define SMB_QUERY_FILE_STANDARD_INFO    0x0102
#define SMB_QUERY_FILE_EA_INFO          0x0103
#define SMB_QUERY_FILE_NAME_INFO        0x0104
#define SMB_QUERY_FILE_ALL_INFO         0x0107
#define SMB_QUERY_FILE_ALT_NAME_INFO    0x0108
#define SMB_QUERY_FILE_STREAM_INFO      0x0109
#define SMB_QUERY_FILE_COMPRESSION_INFO 0x010b

// See MS-SMB Section 2.2.2.3.5
// For added value, see below from MS-FSCC
#define SMB_INFO_PASSTHROUGH  0x03e8
#define SMB_INFO_PT_FILE_STANDARD_INFO  (SMB_INFO_PASSTHROUGH+5)
#define SMB_INFO_PT_FILE_ALL_INFO       (SMB_INFO_PASSTHROUGH+18)
#define SMB_INFO_PT_FILE_STREAM_INFO    (SMB_INFO_PASSTHROUGH+22)
#define SMB_INFO_PT_NETWORK_OPEN_INFO   (SMB_INFO_PASSTHROUGH+34)

struct SmbTrans2QueryFileInfoReqParams
{
    uint16_t fid;
    uint16_t information_level;
};

inline uint16_t SmbTrans2QueryFileInfoReqFid(const SmbTrans2QueryFileInfoReqParams* req)
{
    return snort::alignedNtohs(&req->fid);
}

inline uint16_t SmbTrans2QueryFileInfoReqInfoLevel(const SmbTrans2QueryFileInfoReqParams* req)
{
    return snort::alignedNtohs(&req->information_level);
}

struct SmbQueryInfoStandard
{
    uint16_t CreationDate;
    uint16_t CreationTime;
    uint16_t LastAccessDate;
    uint16_t LastAccessTime;
    uint16_t LastWriteDate;
    uint16_t LastWriteTime;
    uint32_t FileDataSize;
    uint32_t AllocationSize;
    uint16_t Attributes;
};

inline uint32_t SmbQueryInfoStandardFileDataSize(const SmbQueryInfoStandard* q)
{
    return snort::alignedNtohl(&q->FileDataSize);
}

struct SmbQueryInfoQueryEaSize
{
    uint16_t CreationDate;
    uint16_t CreationTime;
    uint16_t LastAccessDate;
    uint16_t LastAccessTime;
    uint16_t LastWriteDate;
    uint16_t LastWriteTime;
    uint32_t FileDataSize;
    uint32_t AllocationSize;
    uint16_t Attributes;
    uint32_t EaSize;
};

inline uint32_t SmbQueryInfoQueryEaSizeFileDataSize(const SmbQueryInfoQueryEaSize* q)
{
    return snort::alignedNtohl(&q->FileDataSize);
}

struct SmbQueryFileStandardInfo
{
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
    uint16_t Reserved;
};

inline uint64_t SmbQueryFileStandardInfoEndOfFile(const SmbQueryFileStandardInfo* q)
{
    return snort::alignedNtohq(&q->EndOfFile);
}

struct SmbQueryFileAllInfo
{
    // Basic Info
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t LastChangeTime;
    uint32_t ExtFileAttributes;
    uint32_t Reserved1;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
    uint16_t Reserved2;
    uint32_t EaSize;
    uint32_t FileNameLength;
};

inline uint64_t SmbQueryFileAllInfoEndOfFile(const SmbQueryFileAllInfo* q)
{
    return snort::alignedNtohq(&q->EndOfFile);
}

struct SmbQueryPTFileAllInfo
{
    // Basic Info
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t LastChangeTime;
    uint32_t ExtFileAttributes;
    uint32_t Reserved1;

    // Standard Info
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
    uint16_t Reserved2;

    // Internal Info
    uint64_t IndexNumber;

    // EA Info
    uint32_t EaSize;

    // Access Info
    uint32_t AccessFlags;

    // Position Info
    uint64_t CurrentByteOffset;

    // Mode Info
    uint32_t Mode;

    // Alignment Info
    uint32_t AlignmentRequirement;

    // Name Info
    uint32_t FileNameLength;
};

inline uint64_t SmbQueryPTFileAllInfoEndOfFile(const SmbQueryPTFileAllInfo* q)
{
    return snort::alignedNtohq(&q->EndOfFile);
}

struct SmbQueryPTNetworkOpenInfo
{
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t LastChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
    uint32_t Reserved;
};

inline uint64_t SmbQueryPTNetworkOpenInfoEndOfFile(const SmbQueryPTNetworkOpenInfo* q)
{
    return snort::alignedNtohq(&q->EndOfFile);
}

struct SmbQueryPTFileStreamInfo
{
    uint32_t NextEntryOffset;
    uint32_t StreamNameLength;
    uint64_t StreamSize;
    uint64_t StreamAllocationSize;
};

inline uint64_t SmbQueryPTFileStreamInfoStreamSize(const SmbQueryPTFileStreamInfo* q)
{
    return snort::alignedNtohq(&q->StreamSize);
}

struct SmbTrans2QueryFileInformationResp
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 */
    uint8_t smb_res2;
    uint16_t smb_bcc;
};

#define SMB_INFO_SET_EAS               0x0002
#define SMB_SET_FILE_BASIC_INFO        0x0101
#define SMB_SET_FILE_DISPOSITION_INFO  0x0102
#define SMB_SET_FILE_ALLOCATION_INFO   0x0103
#define SMB_SET_FILE_END_OF_FILE_INFO  0x0104

// For added value, see above File Information Classes
#define SMB_INFO_PT_SET_FILE_BASIC_FILE_INFO   (SMB_INFO_PASSTHROUGH+4)
#define SMB_INFO_PT_SET_FILE_END_OF_FILE_INFO  (SMB_INFO_PASSTHROUGH+20)

struct SmbTrans2SetFileInfoReqParams
{
    uint16_t fid;
    uint16_t information_level;
    uint16_t reserved;
};

inline uint16_t SmbTrans2SetFileInfoReqFid(const SmbTrans2SetFileInfoReqParams* req)
{
    return snort::alignedNtohs(&req->fid);
}

inline uint16_t SmbTrans2SetFileInfoReqInfoLevel(const SmbTrans2SetFileInfoReqParams* req)
{
    return snort::alignedNtohs(&req->information_level);
}

inline bool SmbSetFileInfoEndOfFile(const uint16_t info_level)
{
    return ((info_level == SMB_SET_FILE_END_OF_FILE_INFO)
           || (info_level == SMB_INFO_PT_SET_FILE_END_OF_FILE_INFO));
}

struct SmbSetFileBasicInfo
{
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint32_t ExtFileAttributes;
    uint32_t Reserved;
};

inline uint32_t SmbSetFileInfoExtFileAttrs(const SmbSetFileBasicInfo* info)
{
    return snort::alignedNtohl(&info->ExtFileAttributes);
}

inline bool SmbSetFileInfoSetFileBasicInfo(const uint16_t info_level)
{
    return ((info_level == SMB_SET_FILE_BASIC_INFO)
           || (info_level == SMB_INFO_PT_SET_FILE_BASIC_FILE_INFO));
}

/********************************************************************
 * SMB_COM_NT_TRANSACT
 ********************************************************************/
#define SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY     0x00000004

struct SmbNtTransactReq
{
    uint8_t smb_wct;
    uint8_t smb_max_setup_count;
    uint16_t smb_res;
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_max_param_count;
    uint32_t smb_max_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint8_t smb_setup_count;
    uint16_t smb_function;
};

struct SmbNtTransactInterimResp
{
    uint8_t smb_wct;
    uint16_t smb_bcc;
};

struct SmbNtTransactResp
{
    uint8_t smb_wct;
    uint8_t smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t smb_setup_count;
};

inline uint16_t SmbNtTransactReqSubCom(const SmbNtTransactReq* req)
{
    return snort::alignedNtohs(&req->smb_function);
}

inline uint8_t SmbNtTransactReqSetupCnt(const SmbNtTransactReq* req)
{
    return req->smb_setup_count;
}

inline uint32_t SmbNtTransactReqTotalParamCnt(const SmbNtTransactReq* req)
{
    return snort::alignedNtohl(&req->smb_total_param_count);
}

inline uint32_t SmbNtTransactReqParamCnt(const SmbNtTransactReq* req)
{
    return snort::alignedNtohl(&req->smb_param_count);
}

inline uint32_t SmbNtTransactReqParamOff(const SmbNtTransactReq* req)
{
    return snort::alignedNtohl(&req->smb_param_offset);
}

inline uint32_t SmbNtTransactReqTotalDataCnt(const SmbNtTransactReq* req)
{
    return snort::alignedNtohl(&req->smb_total_data_count);
}

inline uint32_t SmbNtTransactReqDataCnt(const SmbNtTransactReq* req)
{
    return snort::alignedNtohl(&req->smb_data_count);
}

inline uint32_t SmbNtTransactReqDataOff(const SmbNtTransactReq* req)
{
    return snort::alignedNtohl(&req->smb_data_offset);
}

inline uint32_t SmbNtTransactRespTotalParamCnt(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_total_param_count);
}

inline uint32_t SmbNtTransactRespParamCnt(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_param_count);
}

inline uint32_t SmbNtTransactRespParamOff(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_param_offset);
}

inline uint32_t SmbNtTransactRespParamDisp(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_param_disp);
}

inline uint32_t SmbNtTransactRespTotalDataCnt(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_total_data_count);
}

inline uint32_t SmbNtTransactRespDataCnt(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_data_count);
}

inline uint32_t SmbNtTransactRespDataOff(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_data_offset);
}

inline uint32_t SmbNtTransactRespDataDisp(const SmbNtTransactResp* resp)
{
    return snort::alignedNtohl(&resp->smb_data_disp);
}

struct SmbNtTransactCreateReqParams
{
    uint32_t flags;
    uint32_t root_dir_fid;
    uint32_t desired_access;
    uint64_t allocation_size;
    uint32_t ext_file_attributes;
    uint32_t share_access;
    uint32_t create_disposition;
    uint32_t create_options;
    uint32_t security_descriptor_length;
    uint32_t ea_length;
    uint32_t name_length;
    uint32_t impersonation_level;
    uint8_t security_flags;
};

inline uint64_t SmbNtTransactCreateReqAllocSize(const SmbNtTransactCreateReqParams* req)
{
    return snort::alignedNtohq(&req->allocation_size);
}

inline uint32_t SmbNtTransactCreateReqFileNameLength(const SmbNtTransactCreateReqParams* req)
{
    return snort::alignedNtohl(&req->name_length);
}

inline uint32_t SmbNtTransactCreateReqFileAttrs(const SmbNtTransactCreateReqParams* req)
{
    return snort::alignedNtohl(&req->ext_file_attributes);
}

inline bool SmbNtTransactCreateReqSequentialOnly(const SmbNtTransactCreateReqParams* req)
{
    return (snort::alignedNtohl(&req->create_options) & SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY);
}

struct SmbNtTransactCreateReq
{
    uint8_t smb_wct;
    uint8_t smb_max_setup_count;
    uint16_t smb_res;
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_max_param_count;
    uint32_t smb_max_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint8_t smb_setup_count;    /* Must be 0x00 */
    uint16_t smb_function;      /* NT_TRANSACT_CREATE */
    uint16_t smb_bcc;
};

struct SmbNtTransactCreateRespParams
{
    uint8_t op_lock_level;
    uint8_t reserved;
    uint16_t smb_fid;
    uint32_t create_action;
    uint32_t ea_error_offset;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t last_change_time;
    uint32_t ext_file_attributes;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint16_t resource_type;
    uint16_t nm_pipe_status;
    uint8_t directory;
};

inline uint16_t SmbNtTransactCreateRespFid(const SmbNtTransactCreateRespParams* resp)
{
    return snort::alignedNtohs(&resp->smb_fid);
}

inline uint32_t SmbNtTransactCreateRespCreateAction(const SmbNtTransactCreateRespParams* resp)
{
    return snort::alignedNtohl(&resp->create_action);
}

inline uint64_t SmbNtTransactCreateRespEndOfFile(const SmbNtTransactCreateRespParams* resp)
{
    return snort::alignedNtohq(&resp->end_of_file);
}

inline uint16_t SmbNtTransactCreateRespResourceType(const SmbNtTransactCreateRespParams* resp)
{
    return snort::alignedNtohs(&resp->resource_type);
}

inline bool SmbNtTransactCreateRespDirectory(const SmbNtTransactCreateRespParams* resp)
{
    return (resp->directory ? true : false);
}

struct SmbNtTransactCreateResp
{
    uint8_t smb_wct;
    uint8_t smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t smb_setup_count;    /* 0x00 */
    uint16_t smb_bcc;
};

/********************************************************************
 * SMB_COM_TRANSACTION_SECONDARY
 *  Continuation command for SMB_COM_TRANSACTION requests if all
 *  data wasn't sent.
 ********************************************************************/
struct SmbTransactionSecondaryReq   /* smb_wct = 8 */
{
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_tpscnt;   /* total number of parameter bytes being sent */
    uint16_t smb_tdscnt;   /* total number of data bytes being sent */
    uint16_t smb_pscnt;    /* number of parameter bytes being sent this buffer */
    uint16_t smb_psoff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_psdisp;   /* byte displacement for these parameter bytes */
    uint16_t smb_dscnt;    /* number of data bytes being sent this buffer */
    uint16_t smb_dsoff;    /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_dsdisp;   /* byte displacement for these data bytes */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

inline uint16_t SmbTransactionSecondaryReqTotalDataCnt(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_tdscnt);
}

inline uint16_t SmbTransactionSecondaryReqDataCnt(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_dscnt);
}

inline uint16_t SmbTransactionSecondaryReqDataOff(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_dsoff);
}

inline uint16_t SmbTransactionSecondaryReqDataDisp(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_dsdisp);
}

inline uint16_t SmbTransactionSecondaryReqTotalParamCnt(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_tpscnt);
}

inline uint16_t SmbTransactionSecondaryReqParamCnt(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_pscnt);
}

inline uint16_t SmbTransactionSecondaryReqParamOff(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_psoff);
}

inline uint16_t SmbTransactionSecondaryReqParamDisp(const SmbTransactionSecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_psdisp);
}

/********************************************************************
 * SMB_COM_TRANSACTION2_SECONDARY
 *  Continuation command for SMB_COM_TRANSACTION2 requests if all
 *  data wasn't sent.
 ********************************************************************/
struct SmbTransaction2SecondaryReq
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_fid;
    uint16_t smb_bcc;
};

inline uint16_t SmbTransaction2SecondaryReqTotalParamCnt(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_total_param_count);
}

inline uint16_t SmbTransaction2SecondaryReqParamCnt(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_param_count);
}

inline uint16_t SmbTransaction2SecondaryReqParamOff(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_param_offset);
}

inline uint16_t SmbTransaction2SecondaryReqParamDisp(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_param_disp);
}

inline uint16_t SmbTransaction2SecondaryReqTotalDataCnt(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_total_data_count);
}

inline uint16_t SmbTransaction2SecondaryReqDataCnt(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_data_count);
}

inline uint16_t SmbTransaction2SecondaryReqDataOff(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_data_offset);
}

inline uint16_t SmbTransaction2SecondaryReqDataDisp(const SmbTransaction2SecondaryReq* req)
{
    return snort::alignedNtohs(&req->smb_data_disp);
}

/********************************************************************
 * SMB_COM_NT_TRANSACT_SECONDARY
 ********************************************************************/
struct SmbNtTransactSecondaryReq
{
    uint8_t smb_wct;
    uint8_t smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t smb_res2;
};

inline uint32_t SmbNtTransactSecondaryReqTotalParamCnt(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_total_param_count);
}

inline uint32_t SmbNtTransactSecondaryReqParamCnt(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_param_count);
}

inline uint32_t SmbNtTransactSecondaryReqParamOff(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_param_offset);
}

inline uint32_t SmbNtTransactSecondaryReqParamDisp(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_param_disp);
}

inline uint32_t SmbNtTransactSecondaryReqTotalDataCnt(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_total_data_count);
}

inline uint32_t SmbNtTransactSecondaryReqDataCnt(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_data_count);
}

inline uint32_t SmbNtTransactSecondaryReqDataOff(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_data_offset);
}

inline uint32_t SmbNtTransactSecondaryReqDataDisp(const SmbNtTransactSecondaryReq* req)
{
    return snort::alignedNtohl(&req->smb_data_disp);
}

/********************************************************************
 * SMB_COM_READ_RAW
 ********************************************************************/
struct SmbReadRawReq   /* smb_wct = 8 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return (max 65,535) */
    uint16_t smb_mincnt;     /* min number of bytes to return (normally 0) */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */
};

struct SmbReadRawExtReq   /* smb_wct = 10 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return (max 65,535) */
    uint16_t smb_mincnt;     /* min number of bytes to return (normally 0) */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_rsvd;       /* reserved */
    uint32_t smb_off_high;   /* high offset in file to begin write */
    uint16_t smb_bcc;        /* value = 0 */
};

/* Read Raw response is raw data wrapped in NetBIOS header */

inline uint16_t SmbReadRawReqFid(const SmbReadRawReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint64_t SmbReadRawReqOffset(const SmbReadRawExtReq* req)
{
    if (req->smb_wct == 8)
        return (uint64_t)snort::alignedNtohl(&req->smb_offset);

    return (uint64_t)snort::alignedNtohl(&req->smb_off_high) << 32
                    | (uint64_t)snort::alignedNtohl(&req->smb_offset);
}

/********************************************************************
 * SMB_COM_WRITE_RAW
 ********************************************************************/
struct SmbWriteRawReq
{
    uint8_t smb_wct;       /* value = 12 */
    uint16_t smb_fid;      /* file handle */
    uint16_t smb_tcount;   /* total bytes (including this buf, 65,535 max ) */
    uint16_t smb_rsvd;     /* reserved */
    uint32_t smb_offset;   /* offset in file to begin write */
    uint32_t smb_timeout;  /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;    /* write mode:
                              bit0 - complete write to disk and send final result response
                              bit1 - return smb_remaining (pipes/devices only) */
    uint32_t smb_rsvd2;    /* reserved */
    uint16_t smb_dsize;    /* number of data bytes this buffer (min value = 0) */
    uint16_t smb_doff;     /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

struct SmbWriteRawExtReq
{
    uint8_t smb_wct;       /* value = 14 */
    uint16_t smb_fid;      /* file handle */
    uint16_t smb_tcount;   /* total bytes (including this buf, 65,535 max ) */
    uint16_t smb_rsvd;     /* reserved */
    uint32_t smb_offset;   /* offset in file to begin write */
    uint32_t smb_timeout;  /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;    /* write mode:
                              bit0 - complete write to disk and send final result response
                              bit1 - return smb_remaining (pipes/devices only) */
    uint32_t smb_rsvd2;    /* reserved */
    uint16_t smb_dsize;    /* number of data bytes this buffer (min value = 0) */
    uint16_t smb_doff;     /* offset (from start of SMB hdr) to data bytes */
    uint32_t smb_off_high; /* high offset in file to begin write */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

struct SmbWriteRawInterimResp
{
    uint8_t smb_wct;         /* value = 1 */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint16_t smb_bcc;        /* value = 0 */
};

inline uint16_t SmbWriteRawReqTotalCount(const SmbWriteRawReq* req)
{
    return snort::alignedNtohs(&req->smb_tcount);
}

inline bool SmbWriteRawReqWriteThrough(const SmbWriteRawReq* req)
{
    return snort::alignedNtohs(&req->smb_wmode) & 0x0001;
}

inline uint16_t SmbWriteRawReqFid(const SmbWriteRawReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteRawReqDataOff(const SmbWriteRawReq* req)
{
    return snort::alignedNtohs(&req->smb_doff);
}

inline uint16_t SmbWriteRawReqDataCnt(const SmbWriteRawReq* req)
{
    return snort::alignedNtohs(&req->smb_dsize);
}

inline uint64_t SmbWriteRawReqOffset(const SmbWriteRawExtReq* req)
{
    if (req->smb_wct == 12)
        return (uint64_t)snort::alignedNtohl(&req->smb_offset);

    return (uint64_t)snort::alignedNtohl(&req->smb_off_high) << 32 |
                    (uint64_t)snort::alignedNtohl(&req->smb_offset);
}

inline uint16_t SmbWriteRawInterimRespRemaining(const SmbWriteRawInterimResp* resp)
{
    return snort::alignedNtohs(&resp->smb_remaining);
}

/********************************************************************
 * SMB_COM_WRITE_COMPLETE - final response to an SMB_COM_WRITE_RAW
 ********************************************************************/
struct SmbWriteCompleteResp
{
    uint8_t smb_wct;     /* value = 1 */
    uint16_t smb_count;  /* total number of bytes written */
    uint16_t smb_bcc;    /* value = 0 */
};

inline uint16_t SmbWriteCompleteRespCount(const SmbWriteCompleteResp* resp)
{
    return snort::alignedNtohs(&resp->smb_count);
}

/********************************************************************
 * SMB_COM_WRITE_AND_CLOSE
 ********************************************************************/
struct SmbWriteAndCloseReq   /* smb_wct = 6 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle (close after write) */
    uint16_t smb_count;   /* number of bytes to write */
    uint32_t smb_offset;  /* offset in file to begin write */
    uint32_t smb_mtime;   /* modification time */
    uint16_t smb_bcc;     /* 1 (for pad) + value of smb_count */
};

struct SmbWriteAndCloseExtReq   /* smb_wct = 12 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle (close after write) */
    uint16_t smb_count;   /* number of bytes to write */
    uint32_t smb_offset;  /* offset in file to begin write */
    uint32_t smb_mtime;   /* modification time */
    uint32_t smb_rsvd1;   /* Optional */
    uint32_t smb_rsvd2;   /* Optional */
    uint32_t smb_rsvd3;   /* Optional */
    uint16_t smb_bcc;     /* 1 (for pad) + value of smb_count */
};

struct SmbWriteAndCloseResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;     /* count of 16-bit words that follow */
    uint16_t smb_count;  /* number of bytes written */
    uint16_t smb_bcc;    /* must be 0 */
};

inline uint16_t SmbWriteAndCloseReqFid(const SmbWriteAndCloseReq* req)
{
    return snort::alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteAndCloseReqCount(const SmbWriteAndCloseReq* req)
{
    return snort::alignedNtohs(&req->smb_count);
}

inline uint32_t SmbWriteAndCloseReqOffset(const SmbWriteAndCloseReq* req)
{
    return snort::alignedNtohl(&req->smb_offset);
}

inline uint16_t SmbWriteAndCloseRespCount(const SmbWriteAndCloseResp* resp)
{
    return snort::alignedNtohs(&resp->smb_count);
}

#pragma pack()

void DCE2_SmbInitGlobals();
void DCE2_SmbProcess(struct DCE2_SmbSsnData*);
DCE2_SmbSsnData* dce2_handle_smb_session(snort::Packet*, struct dce2SmbProtoConf*);

#endif

