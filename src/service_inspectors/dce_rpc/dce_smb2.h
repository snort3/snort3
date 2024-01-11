//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "hash/lru_cache_shared.h"
#include "flow/flow_key.h"
#include "main/thread_config.h"
#include "utils/util.h"

#define GET_CURRENT_PACKET snort::DetectionEngine::get_current_packet()

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
    uint32_t process_id;      /* Reserved */
    uint32_t tree_id;         /* Tree id*/
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

    explicit DCE2_Smb2RequestTracker(uint64_t file_id_v, uint64_t offset_v = 0);
    DCE2_Smb2RequestTracker(char* fname_v, uint16_t fname_len_v);
    ~DCE2_Smb2RequestTracker();

    uint64_t get_offset()
    {
        return offset;
    }

    uint64_t get_file_id()
    {
        return file_id;
    }

    void set_file_id(uint64_t fid)
    {
        file_id = fid;
    }

    void set_tree_id(uint32_t l_tree_id)
    {
        tree_id = l_tree_id;
    }

    uint32_t get_tree_id()
    {
        return tree_id;
    }

    void set_session_id(uint32_t l_session_id)
    {
        session_id = l_session_id;
    }

    uint32_t get_session_id()
    {
        return session_id;
    }

    char* fname = nullptr;
    uint16_t fname_len = 0;
    uint64_t file_id = 0;
    uint64_t offset = 0;
    uint32_t tree_id = 0;
    uint64_t session_id = 0;
};

struct DCE2_Smb2SsnData;
class DCE2_Smb2SessionTracker;

class DCE2_Smb2FileTracker
{
public:

    DCE2_Smb2FileTracker() = delete;
    DCE2_Smb2FileTracker(const DCE2_Smb2FileTracker& arg) = delete;
    DCE2_Smb2FileTracker& operator=(const DCE2_Smb2FileTracker& arg) = delete;

    DCE2_Smb2FileTracker(uint64_t file_id_v, DCE2_Smb2TreeTracker* ttr_v,
        DCE2_Smb2SessionTracker* str_v, snort::Flow* flow_v);
    ~DCE2_Smb2FileTracker();
    uint64_t max_offset = 0;
    uint64_t file_id = 0;
    uint64_t file_size = 0;
    uint64_t file_name_hash = 0;
    DCE2_Smb2TreeTracker* ttr = nullptr;
    DCE2_Smb2SessionTracker* str = nullptr;
    snort::Flow* parent_flow = nullptr;
    DCE2_CoTracker* co_tracker = nullptr;
    bool ignore : 1;
    bool upload : 1;
    bool multi_channel_file : 1;
};

class DCE2_Smb2LocalFileTracker
{
public:
    uint64_t file_offset = 0;
    DCE2_SmbPduState smb2_pdu_state = DCE2_SMB_PDU_STATE__COMMAND;
};
typedef DCE2_DbMap<uint64_t, DCE2_Smb2FileTracker*, std::hash<uint64_t> > DCE2_DbMapFtracker;
typedef DCE2_DbMap<uint64_t, DCE2_Smb2RequestTracker*, std::hash<uint64_t> > DCE2_DbMapRtracker;
class DCE2_Smb2TreeTracker
{
public:

    DCE2_Smb2TreeTracker() = delete;
    DCE2_Smb2TreeTracker(const DCE2_Smb2TreeTracker& arg) = delete;
    DCE2_Smb2TreeTracker& operator=(const DCE2_Smb2TreeTracker& arg) = delete;

    DCE2_Smb2TreeTracker (uint32_t tid_v, uint8_t share_type_v);
    ~DCE2_Smb2TreeTracker();

    // File Tracker
    DCE2_Smb2FileTracker* findFtracker(uint64_t file_id)
    {
        return file_trackers.Find(file_id);
    }

    bool insertFtracker(uint64_t file_id, DCE2_Smb2FileTracker* ftracker)
    {
        return file_trackers.Insert(file_id, ftracker);
    }

    void removeFtracker(uint64_t file_id)
    {
        file_trackers.Remove(file_id);
    }

    // common methods
    uint8_t get_share_type()
    {
        return share_type;
    }

    uint32_t get_tid()
    {
        return tid;
    }

    uint8_t share_type = 0;
    uint32_t tid = 0;
    DCE2_DbMapFtracker file_trackers;
};

PADDING_GUARD_BEGIN

struct Smb2SidHashKey
{
    uint32_t cip[4] = {};
    uint32_t sip[4] = {};
    uint32_t mplsLabel = 0;
    int16_t cgroup = 0;
    int16_t sgroup = 0;
    uint32_t addressSpaceId = 0;
    uint16_t vlan_tag = 0;
    uint16_t padding = 0;
    uint64_t sid = 0;
    uint32_t tenant_id = 0;
    uint32_t padding2 = 0;  // NOTE: If this changes, change do_hash too

    bool operator==(const Smb2SidHashKey& other) const
    {
        return( cip[0] == other.cip[0] and
               cip[1] == other.cip[1] and
               cip[2] == other.cip[2] and
               cip[3] == other.cip[3] and
               sip[0] == other.sip[0] and
               sip[1] == other.sip[1] and
               sip[2] == other.sip[2] and
               sip[3] == other.sip[3] and
               mplsLabel == other.mplsLabel and
               cgroup == other.cgroup and
               sgroup == other.sgroup and
               addressSpaceId == other.addressSpaceId and
               vlan_tag == other.vlan_tag and
               sid == other.sid and
               tenant_id == other.tenant_id );
    }
};
PADDING_GUARD_END

//The below value is taken from Hash Key class static hash hardener
#define SMB_KEY_HASH_HARDENER 133824503

struct SmbKeyHash
{
    size_t operator()(const Smb2SidHashKey& key) const
    {
        return do_hash((const uint32_t*)&key);
    }

    size_t operator()(const snort::FlowKey& key) const
    {
        return do_hash_flow_key((const uint32_t*)&key);
    }

private:
    size_t do_hash(const uint32_t* d) const
    {
        uint32_t a, b, c;
        a = b = c = SMB_KEY_HASH_HARDENER;

        a += d[0];  // IPv6 cip[0]
        b += d[1];  // IPv6 cip[1]
        c += d[2];  // IPv6 cip[2]
        mix(a, b, c);

        a += d[3];  // IPv6 cip[3]
        b += d[4];  // IPv6 sip[0]
        c += d[5];  // IPv6 sip[1]
        mix(a, b, c);

        a += d[6];  // IPv6 sip[2]
        b += d[7];  // IPv6 sip[3]
        c += d[8];  // mpls label
        mix(a, b, c);

        a += d[9];  // cgroup and sgroup
        b += d[10]; // addressSpaceId
        c += d[11]; // vlan_tag, padding
        mix(a, b, c);

        a += d[12]; // sid[0]
        b += d[13]; // sid[1]
        c += d[14]; // tenant_id

        // padding2 is ignored.
        finalize(a, b, c);

        return c;
    }

    size_t do_hash_flow_key(const uint32_t* d) const
    {
        uint32_t a, b, c;
        a = b = c = SMB_KEY_HASH_HARDENER;

        a += d[0];   // IPv6 lo[0]
        b += d[1];   // IPv6 lo[1]
        c += d[2];   // IPv6 lo[2]

        mix(a, b, c);

        a += d[3];   // IPv6 lo[3]
        b += d[4];   // IPv6 hi[0]
        c += d[5];   // IPv6 hi[1]

        mix(a, b, c);

        a += d[6];   // IPv6 hi[2]
        b += d[7];   // IPv6 hi[3]
        c += d[8];   // mpls label

        mix(a, b, c);

        a += d[9];   // addressSpaceId
        b += d[10];  // port lo & port hi
        c += d[11];  // group lo & group hi

        mix(a, b, c);

        a += d[12];  // vlan & pad
        b += d[13];  // ip_proto, pkt_type, version, flags

        finalize(a, b, c);

        return c;
    }
};

typedef DCE2_DbMap<uint32_t, DCE2_Smb2TreeTracker*, std::hash<uint32_t> > DCE2_DbMapTtracker;
typedef DCE2_DbMap<uint32_t, DCE2_Smb2SsnData*, std::hash<uint32_t> > DCE2_DbMapConntracker;
class DCE2_Smb2SessionTracker
{
public:

    DCE2_Smb2SessionTracker() = delete;
    DCE2_Smb2SessionTracker(uint64_t sid);
    ~DCE2_Smb2SessionTracker();

    void removeSessionFromAllConnection();
    void update_cache_size(int size);

    // tree tracker
    bool insertTtracker(uint32_t tree_id, DCE2_Smb2TreeTracker* ttr)
    {
        update_cache_size(sizeof(DCE2_Smb2TreeTracker));
        return tree_trackers.Insert(tree_id, ttr);
    }

    DCE2_Smb2TreeTracker* findTtracker(uint32_t tree_id)
    {
        return tree_trackers.Find(tree_id);
    }

    void removeTtracker(uint32_t tree_id)
    {
        update_cache_size(-(int)sizeof(DCE2_Smb2TreeTracker));
        tree_trackers.Remove(tree_id);
    }

    // ssd tracker
    bool insertConnectionTracker(const uint32_t key, DCE2_Smb2SsnData* ssd)
    {
        return conn_trackers.Insert(key, ssd);
    }

    DCE2_Smb2SsnData* findConnectionTracker(const uint32_t key)
    {
        return conn_trackers.Find(key);
    }

    void removeConnectionTracker(const uint32_t key)
    {
        conn_trackers.Remove(key);
    }

    int getConnTrackerSize()
    {
        return conn_trackers.GetSize();
    }

    void set_encryption_flag(bool flag)
    {
        if (flag)
            encryption_flag++;
        if (encryption_flag == 1)
            dce2_smb_stats.total_encrypted_sessions++;
    }

    bool get_encryption_flag() { return static_cast<bool>(encryption_flag); }

    DCE2_DbMapConntracker conn_trackers;
    DCE2_DbMapTtracker tree_trackers;
    uint64_t session_id = 0;
    uint8_t encryption_flag = 0;
};
struct DCE2_Smb2SsnData
{
    DCE2_SsnData sd;  // This member must be first
    uint8_t smb_id;
    DCE2_Policy policy;
    int dialect_index;
    int ssn_state_flags;
    int64_t max_file_depth; // Maximum file depth as returned from file API
    int16_t max_outstanding_requests; // Maximum number of request that can stay pending
    std::unordered_map<uint64_t, std::weak_ptr<DCE2_Smb2SessionTracker>, std::hash<uint64_t> > session_trackers;
    DCE2_Smb2FileTracker* ftracker_tcp; //To keep tab of current file being transferred over TCP
    std::unique_ptr<DCE2_Smb2LocalFileTracker> ftracker_local;
    DCE2_DbMapRtracker req_trackers;
    uint32_t flow_key;
    snort::Flow* flow = nullptr;
    DCE2_Smb2SsnData();
    ~DCE2_Smb2SsnData();
    void set_reassembled_data(uint8_t* nb_ptr, uint16_t co_len);

    std::shared_ptr<DCE2_Smb2SessionTracker> find_session_tracker(uint64_t session_id)
    {
        auto session_iter = session_trackers.find(session_id);
        if (session_iter != session_trackers.end())
        {
            return session_iter->second.lock();
        }
        return nullptr;
    }

    void remove_session_tracker(uint64_t session_id)
    {
        session_trackers.erase(session_id);
    }

    bool insert_session_tracker(uint64_t session_id, std::shared_ptr<DCE2_Smb2SessionTracker> sptr)
    {
        return session_trackers.insert(std::make_pair(session_id, sptr)).second;
    }

    // Request Tracker
    DCE2_Smb2RequestTracker* findRtracker(uint64_t mid)
    {
        return req_trackers.Find(mid);
    }

    bool insertRtracker(uint64_t message_id, DCE2_Smb2RequestTracker* rtracker)
    {
        return req_trackers.Insert(message_id, rtracker);
    }

    void removeRtracker(uint64_t message_id)
    {
        req_trackers.Remove(message_id);
    }

    int getTotalRequestsPending()
    {
        return req_trackers.GetSize();
    }

    DCE2_Smb2TreeTracker* GetTreeTrackerFromMessage(uint64_t mid)
    {
        DCE2_Smb2RequestTracker* request_tracker = findRtracker(mid);
        if (request_tracker)
        {
            auto session_tracker = find_session_tracker(request_tracker->get_session_id());
            if (session_tracker)
            {
                return session_tracker->findTtracker(request_tracker->get_tree_id());
            }
        }
        return nullptr;
    }
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
#define SMB2_COM_MAX              0x13

struct Smb2NegotiateResponseHdr
{
    uint16_t structure_size;
    uint16_t security_mode;
    uint16_t dialect_revision;
    uint16_t negotiate_context_count;
    uint64_t servier_guid[2];
    uint32_t capabilities;
    uint32_t max_transaction_size;
    uint32_t max_read_size;
    uint32_t max_write_size;
    uint64_t system_time;
    uint64_t server_start_time;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
};

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

// file attribute for create response
#define SMB2_CREATE_RESPONSE_DIRECTORY 0x10

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

struct Smb2CreateContextHdr
{
    uint32_t next;            /* next context header*/
    uint16_t name_offset;     /* name offset */
    uint16_t name_length;     /* name length */
    uint16_t reserved;        /* reserved */
    uint16_t data_offset;     /* data offset */
    uint32_t data_length;     /* data length */
};

struct Smb2IoctlRequestHdr
{
    uint16_t structure_size;          /* This MUST be set to 57 */
    uint16_t reserved;
    uint32_t ctl_code;
    uint64_t fileId_persistent;       /* fileId that is persistent */
    uint64_t fileId_volatile;
    uint32_t input_offset;
    uint32_t input_count;
    uint32_t max_input_response;
    uint32_t output_offset;
    uint32_t output_count;
    uint32_t max_output_response;
    uint32_t flags;
    uint32_t reserved2;
};

struct Smb2IoctlResponseHdr
{
    uint16_t structure_size;           /* This MUST be set to 49 */
    uint16_t reserved;
    uint32_t ctl_code;
    uint64_t fileId_persistent;       /* fileId that is persistent */
    uint64_t fileId_volatile;
    uint32_t input_offset;
    uint32_t input_count;
    uint32_t output_offset;
    uint32_t output_count;
    uint32_t flags;
    uint32_t reserved2;
};

#define SMB2_HEADER_LENGTH 64
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL 0x08

#define SMB2_ERROR_RESPONSE_STRUC_SIZE 9
#define SMB2_NEGOTIATE_RESPONSE_STRUC_SIZE 65

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

#define SMB2_FILE_ALLOCATION_INFO 0x13
#define SMB2_FILE_ENDOFFILE_INFO 0x14

#define SMB2_SETUP_REQUEST_STRUC_SIZE 25
#define SMB2_SETUP_RESPONSE_STRUC_SIZE 9

#define SMB2_IOCTL_REQUEST_STRUC_SIZE 57
#define SMB2_IOCTL_RESPONSE_STRUC_SIZE 49

#define SMB2_LOGOFF_REQUEST_STRUC_SIZE 4

#define SMB2_FLAGS_ASYNC_COMMAND  0x00000002

#define SMB2_STATUS_PENDING  0x00000103

#define FSCTL_PIPE_WAIT 0x00110018
#define FSCTL_PIPE_TRANSCEIVE 0x0011C017
#define FSCTL_PIPE_PEEK 0x0011400C

#define SMB2_CREATE_DURABLE_RECONNECT "DHnC"
#define SMB2_CREATE_DURABLE_RECONNECT_V2 "DH2C"

extern const char* smb2_command_string[SMB2_COM_MAX];
/* Process smb2 message */
void DCE2_Smb2Process(DCE2_Smb2SsnData* ssd);

/* Check smb version based on smb header */
DCE2_SmbVersion DCE2_Smb2Version(const snort::Packet* p);

#endif  /* _DCE_SMB2_H_ */

