//--------------------------------------------------------------------------
// Copyright (C) 2015-2020 Cisco and/or its affiliates. All rights reserved.
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

#include "dce_db.h"
#include "dce_smb.h"
#include "utils/util.h"

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

class DCE2_Smb2TreeTracker;

class DCE2_Smb2RequestTracker
{
public:

    DCE2_Smb2RequestTracker() = delete;
    DCE2_Smb2RequestTracker(const DCE2_Smb2RequestTracker& arg) = delete;
    DCE2_Smb2RequestTracker& operator=(const DCE2_Smb2RequestTracker& arg) = delete;

    DCE2_Smb2RequestTracker(uint64_t offset_v, uint64_t file_id_v,
        char* fname_v, uint16_t fname_len_v, DCE2_Smb2TreeTracker *ttr) :
        fname_len(fname_len_v), fname(fname_v), offset(offset_v),
        file_id(file_id_v), tree_trk(ttr)
    {
        // fname allocated by DCE2_SmbGetFileName
    }

    ~DCE2_Smb2RequestTracker()
    {
        if (fname != nullptr)
        {
            snort_free((void*)fname);
        }
    }

    uint16_t get_file_name_len() { return fname_len; }
    char* get_file_name()  { return fname; }
    uint64_t get_offset() { return offset; }
    uint64_t get_file_id() { return file_id; }
    DCE2_Smb2TreeTracker* get_tree_tracker() { return tree_trk; }

private:

    uint16_t fname_len;
    char* fname;
    uint64_t offset;
    uint64_t file_id;
    DCE2_Smb2TreeTracker* tree_trk;
};

class DCE2_Smb2FileTracker
{
public:

    DCE2_Smb2FileTracker() = delete;
    DCE2_Smb2FileTracker(const DCE2_Smb2FileTracker& arg) = delete;
    DCE2_Smb2FileTracker& operator=(const DCE2_Smb2FileTracker& arg) = delete;

    DCE2_Smb2FileTracker(uint64_t file_id_v, char* file_name_v,
         uint64_t file_size_v) : file_id(file_id_v), file_size(file_size_v)
    {
        if (file_name_v)
            file_name.assign(file_name_v);

        file_offset = 0;
        bytes_processed = 0;
    }

    ~DCE2_Smb2FileTracker()
    {
        // Nothing to be done
    }

    uint64_t bytes_processed;
    uint64_t file_offset;
    uint64_t file_id;
    uint64_t file_size = 0;
    std::string file_name;
    DCE2_SmbPduState smb2_pdu_state;
};


typedef DCE2_DbMap<uint64_t, DCE2_Smb2FileTracker*, std::hash<uint64_t> > DCE2_DbMapFtracker;
typedef DCE2_DbMap<uint64_t, DCE2_Smb2RequestTracker*, std::hash<uint64_t> > DCE2_DbMapRtracker;
class DCE2_Smb2TreeTracker
{
public:

    DCE2_Smb2TreeTracker() = delete;
    DCE2_Smb2TreeTracker(const DCE2_Smb2TreeTracker& arg) = delete;
    DCE2_Smb2TreeTracker& operator=(const DCE2_Smb2TreeTracker& arg) = delete;

    DCE2_Smb2TreeTracker (uint32_t tid_v, uint8_t share_type_v) : share_type(
            share_type_v), tid(tid_v)
    {
    }

    DCE2_Smb2FileTracker* findFtracker(uint64_t file_id)
    {
        return file_trackers.Find(file_id);
    }

    void insertFtracker(uint64_t file_id, DCE2_Smb2FileTracker* ftracker)
    {
        file_trackers.Insert(file_id, ftracker);
    }

    void removeFtracker(uint64_t file_id)
    {
        removeDataRtrackerWithFid(file_id);
        file_trackers.Remove(file_id);
    }

    DCE2_Smb2RequestTracker* findDataRtracker(uint64_t message_id)
    {
        return request_trackers.Find(message_id);
    }

    void insertDataRtracker(uint64_t message_id, DCE2_Smb2RequestTracker* readtracker)
    {
        request_trackers.Insert(message_id, readtracker);
    }

    void removeDataRtracker(uint64_t message_id)
    {
        if (findDataRtracker(message_id))
        {
            request_trackers.Remove(message_id);
        }
    }

    void removeDataRtrackerWithFid(uint64_t fid)
    {
        auto all_requests = request_trackers.get_all_entry();
        for ( auto & h : all_requests )
        {
            if (h.second->get_file_id() == fid)
                removeDataRtracker(h.first); // this is message id
        }
    }

    int getDataRtrackerSize()
    {
        return request_trackers.GetSize();
    }

    uint8_t get_share_type() { return share_type; }
    uint32_t get_tid() { return tid; }
private:
    uint8_t share_type;
    uint32_t tid;

    DCE2_DbMapRtracker request_trackers;
    DCE2_DbMapFtracker file_trackers;
};

typedef DCE2_DbMap<uint32_t, DCE2_Smb2TreeTracker*, std::hash<uint32_t> > DCE2_DbMapTtracker;
class DCE2_Smb2SessionTracker
{
public:

    DCE2_Smb2SessionTracker() { }

    void insertTtracker(uint32_t tree_id, DCE2_Smb2TreeTracker* ttr)
    {
        tree_trackers.Insert(tree_id, ttr);
    }

    DCE2_Smb2TreeTracker* findTtracker(uint32_t tree_id)
    {
        return tree_trackers.Find(tree_id);
    }

    void removeTtracker(uint32_t tree_id)
    {
        // Remove any dangling request trackers with tree id
        removeRtrackerWithTid(tree_id);
        tree_trackers.Remove(tree_id);
    }

    DCE2_Smb2RequestTracker* findRtracker(uint64_t mid)
    {
        return create_request_trackers.Find(mid);
    }

    void insertRtracker(uint64_t message_id, DCE2_Smb2RequestTracker* rtracker)
    {
        create_request_trackers.Insert(message_id, rtracker);
    }

    void removeRtracker(uint64_t message_id)
    {
        create_request_trackers.Remove(message_id);
    }

    void removeRtrackerWithTid(uint32_t tid)
    {
        auto all_requests = create_request_trackers.get_all_entry();
        for ( auto & h : all_requests )
        {
            if (h.second->get_tree_tracker() and h.second->get_tree_tracker()->get_tid() == tid)
                removeRtracker(h.first); // this is message id
        }
    }

    uint16_t getTotalRequestsPending()
    {
        uint16_t total_count = 0;
        auto all_tree_trackers = tree_trackers.get_all_entry();
        for ( auto & h : all_tree_trackers )
        {
            total_count += h.second->getDataRtrackerSize(); // all read/write
        }
        total_count += create_request_trackers.GetSize(); // all create
        return total_count;
    }

    void set_session_id(uint64_t sid) { session_id = sid; }
    uint64_t get_session_id() { return session_id; }

private:
    uint64_t session_id;
    DCE2_DbMapTtracker tree_trackers;
    DCE2_DbMapRtracker create_request_trackers;
};

typedef DCE2_DbMap<uint64_t, DCE2_Smb2SessionTracker*, std::hash<uint64_t> > DCE2_DbMapStracker;
struct DCE2_Smb2SsnData
{
    DCE2_SsnData sd;  // This member must be first
    uint8_t smb_id;
    DCE2_Policy policy;
    int dialect_index;
    int ssn_state_flags;
    int64_t max_file_depth; // Maximum file depth as returned from file API
    int16_t max_outstanding_requests; // Maximum number of request that can stay pending
    DCE2_DbMapStracker session_trackers;
    DCE2_Smb2FileTracker* ftracker_tcp; //To keep tab of current file being transferred over TCP
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
    uint64_t fileId_persistent; /* fileId that is persistent */
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

struct  Smb2SetupRequestHdr
{
    uint16_t structure_size;            /* This MUST be set to 25 (0x19) bytes */
    uint8_t flags;
    uint8_t security_mode;
    uint32_t capabilities;
    uint32_t channel;
    uint16_t secblob_ofs;
    uint16_t secblob_size;
    uint64_t previous_sessionid;
};

struct Smb2SetupResponseHdr
{
    uint16_t structure_size;            /* This MUST be set to 9 (0x09) bytes */
    uint16_t session_flags;
    uint16_t secblob_ofs;
    uint16_t secblob_size;
};

#define SMB2_HEADER_LENGTH 64

#define SMB2_ERROR_RESPONSE_STRUC_SIZE 9

#define SMB2_CREATE_REQUEST_STRUC_SIZE 57
#define SMB2_CREATE_RESPONSE_STRUC_SIZE 89
#define SMB2_CREATE_REQUEST_DATA_OFFSET 120

#define SMB2_CLOSE_REQUEST_STRUC_SIZE 24
#define SMB2_CLOSE_RESPONSE_STRUC_SIZE 60

#define SMB2_WRITE_REQUEST_STRUC_SIZE 49
#define SMB2_WRITE_RESPONSE_STRUC_SIZE 17

#define SMB2_READ_REQUEST_STRUC_SIZE 49
#define SMB2_READ_RESPONSE_STRUC_SIZE 17

#define SMB2_SET_INFO_REQUEST_STRUC_SIZE 33
#define SMB2_SET_INFO_RESPONSE_STRUC_SIZE 2

#define SMB2_TREE_CONNECT_REQUEST_STRUC_SIZE 9
#define SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE 16
#define SMB2_TREE_DISCONNECT_REQUEST_STRUC_SIZE 4

#define SMB2_FILE_ENDOFFILE_INFO 0x14

#define SMB2_SETUP_REQUEST_STRUC_SIZE 25
#define SMB2_SETUP_RESPONSE_STRUC_SIZE 9

#define SMB2_LOGOFF_REQUEST_STRUC_SIZE 4

/* Process smb2 message */
void DCE2_Smb2Process(DCE2_Smb2SsnData* ssd);

/* Check smb version based on smb header */
DCE2_SmbVersion DCE2_Smb2Version(const snort::Packet* p);

#endif  /* _DCE_SMB2_H_ */

