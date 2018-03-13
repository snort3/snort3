//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// SMB2 file processing
// Author(s):  Hui Cao <huica@cisco.com>

#ifndef DCE_SMB2_H
#define DCE_SMB2_H

#include "dce_smb.h"

#define SMB2_FLAGS_ASYNC_COMMAND  0x00000002

struct Smb2Hdr
{
    uint8_t smb_idf[4];       /* contains 0xFE,’SMB’ */
    uint16_t structure_size;  /* This MUST be set to 64 */
    uint16_t credit_charge;   /* # of credits that this request consumes */
    uint32_t status;          /* depends */
    uint16_t command;         /* command code  */
    uint16_t credit;          /* # of credits requesting/granted */
    uint32_t flags;           /* flags */
    uint32_t next_command;    /* used for compounded request */
    uint64_t message_id;      /* identifies a message uniquely on connection */
    uint64_t async_sync;      /* used for async and sync differently */
    uint64_t session_id;      /* identifies the established session for the command*/
    uint8_t signature[16];    /* signature of the message */
};

struct Smb2ASyncHdr
{
    uint8_t smb_idf[4];       /* contains 0xFE,’SMB’ */
    uint16_t structure_size;  /* This MUST be set to 64 */
    uint16_t credit_charge;   /* # of credits that this request consumes */
    uint32_t status;          /* depends */
    uint16_t command;         /* command code  */
    uint16_t credit;          /* # of credits requesting/granted */
    uint32_t flags;           /* flags */
    uint32_t next_command;    /* used for compounded request */
    uint64_t message_id;      /* identifies a message uniquely on connection */
    uint64_t async_id;        /* handle operations asynchronously */
    uint64_t session_id;      /* identifies the established session for the command*/
    uint8_t signature[16];    /* signature of the message */
};

struct Smb2SyncHdr
{
    uint8_t smb_idf[4];       /* contains 0xFE,’SMB’ */
    uint16_t structure_size;  /* This MUST be set to 64 */
    uint16_t credit_charge;   /* # of credits that this request consumes */
    uint32_t status;          /* depends */
    uint16_t command;         /* command code  */
    uint16_t credit;          /* # of credits requesting/granted */
    uint32_t flags;           /* flags */
    uint32_t next_command;    /* used for compounded request */
    uint64_t message_id;      /* identifies a message uniquely on connection */
    uint32_t reserved;        /* reserved */
    uint32_t tree_id;         /* identifies the tree connect for the command */
    uint64_t session_id;      /* identifies the established session for the command*/
    uint8_t signature[16];    /* signature of the message */
};

struct Smb2ErrorResponseHdr
{
    uint16_t structure_size;  /* This MUST be set to 9 */
    uint16_t reserved;        /* reserved */
    uint32_t byte_count;      /* The number of bytes of error_data */
    uint8_t error_data[1];    /* If byte_count is 0, this MUST be 0*/
};

/* SMB2 command codes */
#define SMB2_COM_NEGOTIATE        0x00
#define SMB2_COM_SESSION_SETUP    0x01
#define SMB2_COM_LOGOFF           0x02
#define SMB2_COM_TREE_CONNECT     0x03
#define SMB2_COM_TREE_DISCONNECT  0x04
#define SMB2_COM_CREATE           0x05
#define SMB2_COM_CLOSE            0x06
#define SMB2_COM_FLUSH            0x07
#define SMB2_COM_READ             0x08
#define SMB2_COM_WRITE            0x09
#define SMB2_COM_LOCK             0x0A
#define SMB2_COM_IOCTL            0x0B
#define SMB2_COM_CANCEL           0x0C
#define SMB2_COM_ECHO             0x0D
#define SMB2_COM_QUERY_DIRECTORY  0x0E
#define SMB2_COM_CHANGE_NOTIFY    0x0F
#define SMB2_COM_QUERY_INFO       0x10
#define SMB2_COM_SET_INFO         0x11
#define SMB2_COM_OPLOCK_BREAK     0x12

struct Smb2WriteRequestHdr
{
    uint16_t structure_size;  /* This MUST be set to 49 */
    uint16_t data_offset;     /* offset in bytes from the beginning of smb2 header */
    uint32_t length;          /* length of data being written in bytes */
    uint64_t offset;          /* offset in the destination file */
    uint64_t fileId_persistent;  /* fileId that is persistent */
    uint64_t fileId_volatile;    /* fileId that is volatile */
    uint32_t channel;            /* channel */
    uint32_t remaining_bytes;    /* subsequent bytes the client intends to write*/
    uint16_t write_channel_info_offset;      /* channel data info */
    uint16_t write_channel_info_length;      /* channel data info */
    uint32_t flags;      /* flags*/
};

struct Smb2WriteResponseHdr
{
    uint16_t structure_size;  /* This MUST be set to 17 */
    uint16_t reserved;        /* reserved */
    uint32_t count;           /* The number of bytes written */
    uint32_t remaining;       /* MUST be 0*/
    uint16_t write_channel_info_offset;      /* channel data info */
    uint16_t write_channel_info_length;      /* channel data info */
};

struct Smb2ReadRequestHdr
{
    uint16_t structure_size;  /* This MUST be set to 49 */
    uint8_t padding;          /* Padding */
    uint8_t flags;            /* Flags */
    uint32_t length;          /* length of data to read from the file */
    uint64_t offset;          /* offset in the destination file */
    uint64_t fileId_persistent;  /* fileId that is persistent */
    uint64_t fileId_volatile;    /* fileId that is volatile */
    uint32_t minimum_count;      /* The minimum # of bytes to be read */
    uint32_t channel;            /* channel */
    uint32_t remaining_bytes;    /* subsequent bytes the client intends to read*/
    uint16_t read_channel_info_offset;      /* channel data info */
    uint16_t read_channel_info_length;      /* channel data info */
};

struct Smb2ReadResponseHdr
{
    uint16_t structure_size; /* This MUST be set to 17 */
    uint8_t data_offset;     /* offset in bytes from beginning of smb2 header*/
    uint8_t reserved;        /* reserved */
    uint32_t length;         /* The number of bytes being returned in response */
    uint32_t remaining;      /* The number of data being sent on the channel*/
    uint32_t reserved2;      /* reserved */
};

struct Smb2SetInfoRequestHdr
{
    uint16_t structure_size;   /* This MUST be set to 33 */
    uint8_t info_type;         /* info type */
    uint8_t file_info_class;   /* file info class after header */
    uint32_t buffer_length;    /* buffer length */
    uint16_t buffer_offset;    /* buffer offset */
    uint16_t reserved;         /* reserved */
    uint32_t additional_info;  /* additional information */
    uint64_t fileId_persistent;/* fileId that is persistent */
    uint64_t fileId_volatile;  /* fileId that is volatile */
};

struct Smb2CreateRequestHdr
{
    uint16_t structure_size;          /* This MUST be set to 57 */
    uint8_t security_flags;           /* security flag, should be 0 */
    uint8_t requested_oplock_level;   /* */
    uint32_t impersonation_level;     /* */
    uint64_t smb_create_flags;        /* should be 0 */
    uint64_t reserved;                /* can be any value */
    uint32_t desired_access;          /*  */
    uint32_t file_attributes;         /* */
    uint32_t share_access;            /* READ WRITE DELETE etc */
    uint32_t create_disposition;      /* actions when file exists*/
    uint32_t create_options;          /* options for creating file*/
    uint16_t name_offset;             /* file name offset from SMB2 header */
    uint16_t name_length;             /* length of file name */
    uint32_t create_contexts_offset;  /* offset of contexts from beginning of header */
    uint32_t create_contexts_length;  /* length of contexts */
};

struct Smb2CreateResponseHdr
{
    uint16_t structure_size;          /* This MUST be set to 89 */
    uint8_t oplock_level;             /* oplock level granted, values limited */
    uint8_t flags;                    /* flags, values limited */
    uint32_t create_action;           /* action taken, values limited */
    uint64_t creation_time;           /* time created */
    uint64_t last_access_time;        /* access time */
    uint64_t last_write_time;         /* write  time */
    uint64_t change_time;             /* time modified*/
    uint64_t allocation_size;         /* size allocated */
    uint64_t end_of_file;             /* file size*/
    uint32_t file_attributes;         /* attributes of the file*/
    uint32_t reserved2;               /* */
    uint64_t fileId_persistent;       /* fileId that is persistent */
    uint64_t fileId_volatile;         /* fileId that is volatile */
    uint32_t create_contexts_offset;  /*  */
    uint32_t create_contexts_length;  /*  */
};

struct Smb2CloseRequestHdr
{
    uint16_t structure_size;          /* This MUST be set to 24 */
    uint16_t flags;                   /* flags */
    uint32_t reserved;                /* can be any value */
    uint64_t fileId_persistent;       /* fileId that is persistent */
    uint64_t fileId_volatile;         /* fileId that is volatile */
};

#define SMB2_SHARE_TYPE_DISK  0x01
#define SMB2_SHARE_TYPE_PIPE  0x02
#define SMB2_SHARE_TYPE_PRINT 0x03

struct Smb2TreeConnectResponseHdr
{
    uint16_t structure_size;          /* This MUST be set to 16 */
    uint8_t share_type;               /* type of share being accessed */
    uint8_t reserved;                 /* reserved */
    uint32_t share_flags;             /* properties for this share*/
    uint32_t capabilities;            /* various capabilities for this share */
    uint32_t maximal_access;          /* maximal access for the user */
};

struct Smb2TreeDisConnectHdr
{
    uint16_t structure_size;          /* This MUST be set to 4 */
    uint16_t reserved;                 /* reserved */
};

#define SMB2_HEADER_LENGTH 64

#define SMB2_ERROR_RESPONSE_STRUC_SIZE 9

#define SMB2_CREATE_REQUEST_STRUC_SIZE 57
#define SMB2_CREATE_RESPONSE_STRUC_SIZE 89
#define SMB2_CREATE_REQUEST_DATA_OFFSET 120

#define SMB2_CLOSE_REQUEST_STRUC_SIZE 24

#define SMB2_WRITE_REQUEST_STRUC_SIZE 49
#define SMB2_WRITE_RESPONSE_STRUC_SIZE 17

#define SMB2_READ_REQUEST_STRUC_SIZE 49
#define SMB2_READ_RESPONSE_STRUC_SIZE 17

#define SMB2_SET_INFO_REQUEST_STRUC_SIZE 33
#define SMB2_SET_INFO_RESPONSE_STRUC_SIZE 2

#define SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE 16
#define SMB2_TREE_DISCONNECT_STRUC_SIZE 4

#define SMB2_FILE_ENDOFFILE_INFO 0x14

/* Clean up all the pending requests*/
void DCE2_Smb2CleanRequests(Smb2Request* requests);

/* Process smb2 message */
void DCE2_Smb2Process(DCE2_SmbSsnData* ssd);

/* Initialize file tracker for smb2 processing */
DCE2_Ret DCE2_Smb2InitFileTracker(DCE2_SmbFileTracker* ftracker,
    const bool is_ipc, const uint64_t fid);

/* Check smb version based on smb header */
DCE2_SmbVersion DCE2_Smb2Version(const snort::Packet* p);

#endif  /* _DCE_SMB2_H_ */

