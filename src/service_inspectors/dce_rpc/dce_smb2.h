//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// This implements smb session data for SMBv2
// Also provides SMBv2 related header structures

#include "main/thread_config.h"
#include "memory/memory_cap.h"
#include "utils/util.h"
#include <mutex>

#include "dce_smb_common.h"

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

extern const char* smb2_command_string[SMB2_COM_MAX];

// file attribute for create response
#define SMB2_CREATE_RESPONSE_DIRECTORY 0x10
#define SMB_AVG_FILES_PER_SESSION 5

#define SMB2_SHARE_TYPE_DISK  0x01
#define SMB2_SHARE_TYPE_PIPE  0x02
#define SMB2_SHARE_TYPE_PRINT 0x03

#define SMB2_CMD_TYPE_ERROR_RESPONSE 0
#define SMB2_CMD_TYPE_REQUEST        1
#define SMB2_CMD_TYPE_RESPONSE       2
#define SMB2_CMD_TYPE_INVALID        3

#define FSCTL_PIPE_WAIT 0x00110018
#define FSCTL_PIPE_TRANSCEIVE 0x0011C017
#define FSCTL_PIPE_PEEK 0x0011400C

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

struct Smb2CreateContextHdr
{
    uint32_t next;            /* next context header*/
    uint16_t name_offset;     /* name offset */
    uint16_t name_length;     /* name length */
    uint16_t reserved;        /* reserved */
    uint16_t data_offset;     /* data offset */
    uint32_t data_length;     /* data length */
};

struct Smb2CloseRequestHdr
{
    uint16_t structure_size;          /* This MUST be set to 24 */
    uint16_t flags;                   /* flags */
    uint32_t reserved;                /* can be any value */
    uint64_t fileId_persistent;       /* fileId that is persistent */
    uint64_t fileId_volatile;         /* fileId that is volatile */
};

struct Smb2TreeConnectResponseHdr
{
    uint16_t structure_size;          /* This MUST be set to 16 */
    uint8_t share_type;               /* type of share being accessed */
    uint8_t reserved;                 /* reserved */
    uint32_t share_flags;             /* properties for this share*/
    uint32_t capabilities;            /* various capabilities for this share */
    uint32_t maximal_access;          /* maximal access for the user */
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

#define SMB2_ERROR_RESPONSE_STRUC_SIZE 9

#define SMB2_NEGOTIATE_REQUEST_STRUC_SIZE 36
#define SMB2_NEGOTIATE_RESPONSE_STRUC_SIZE 65

#define SMB2_CREATE_REQUEST_STRUC_SIZE 57
#define SMB2_CREATE_RESPONSE_STRUC_SIZE 89

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
#define SMB2_TREE_DISCONNECT_RESPONSE_STRUC_SIZE 4

#define SMB2_SETUP_REQUEST_STRUC_SIZE 25
#define SMB2_SETUP_RESPONSE_STRUC_SIZE 9

#define SMB2_LOGOFF_REQUEST_STRUC_SIZE 4
#define SMB2_LOGOFF_RESPONSE_STRUC_SIZE 4

#define SMB2_IOCTL_REQUEST_STRUC_SIZE 57
#define SMB2_IOCTL_RESPONSE_STRUC_SIZE 49

#define SMB2_FILE_ENDOFFILE_INFO 0x14
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL 0x08

#define GET_CURRENT_PACKET snort::DetectionEngine::get_current_packet()

class Dce2Smb2FileTracker;
class Dce2Smb2SessionTracker;

using Dce2Smb2SessionTrackerPtr = std::shared_ptr<Dce2Smb2SessionTracker>;
using Dce2Smb2SessionTrackerMap =
    std::unordered_map<uint64_t, Dce2Smb2SessionTrackerPtr, std::hash<uint64_t> >;

using Dce2Smb2FileTrackerPtr = std::shared_ptr<Dce2Smb2FileTracker>;
using Dce2Smb2FileTrackerMap =
    std::unordered_map<uint64_t, Dce2Smb2FileTrackerPtr, std::hash<uint64_t> >;

PADDING_GUARD_BEGIN
struct Smb2SessionKey
{
    uint32_t cip[4];
    uint32_t sip[4];
    uint64_t sid;
    int16_t cgroup;
    int16_t sgroup;
    uint16_t asid;
    uint16_t padding;

    bool operator==(const Smb2SessionKey& other) const
    {
        return( sid == other.sid and
               cip[0] == other.cip[0] and
               cip[1] == other.cip[1] and
               cip[2] == other.cip[2] and
               cip[3] == other.cip[3] and
               sip[0] == other.sip[0] and
               sip[1] == other.sip[1] and
               sip[2] == other.sip[2] and
               sip[3] == other.sip[3] and
               cgroup == other.cgroup and
               sgroup == other.sgroup and
               asid == other.asid );
    }
};

struct Smb2FlowKey
{
    uint32_t ip_l[4];   // Low IP
    uint32_t ip_h[4];   // High IP
    uint32_t mplsLabel;
    uint16_t port_l;    // Low Port - 0 if ICMP
    uint16_t port_h;    // High Port - 0 if ICMP
    int16_t group_l;
    int16_t group_h;
    uint16_t vlan_tag;
    uint16_t addressSpaceId;
    uint8_t ip_protocol;
    uint8_t pkt_type;
    uint8_t version;
    uint8_t padding;
};

struct Smb2MessageKey
{
    uint64_t mid;
    uint32_t flow_key;
    uint32_t padding;

    bool operator==(const Smb2MessageKey& other) const
    {
        return (mid == other.mid and
               flow_key == other.flow_key);
    }
};
PADDING_GUARD_END

//The below value is taken from Hash Key class static hash hardener
#define SMB_KEY_HASH_HARDENER 133824503

struct Smb2KeyHash
{
    size_t operator()(const Smb2FlowKey& key) const
    {
        return do_hash_flow_key((const uint32_t*)&key);
    }

    size_t operator()(const Smb2SessionKey& key) const
    {
        return do_hash_session_key((const uint32_t*)&key);
    }

    size_t operator()(const Smb2MessageKey& key) const
    {
        return do_hash_message_key((const uint32_t*)&key);
    }

private:
    size_t do_hash_flow_key(const uint32_t* d) const
    {
        uint32_t a, b, c;
        a = b = c = SMB_KEY_HASH_HARDENER;
        a += d[0]; b += d[1];  c += d[2];  mix(a, b, c);
        a += d[3]; b += d[4];  c += d[5];  mix(a, b, c);
        a += d[6]; b += d[7];  c += d[8];  mix(a, b, c);
        a += d[9]; b += d[10]; c += d[11]; mix(a, b, c);
        a += d[12]; finalize(a, b, c);
        return c;
    }

    size_t do_hash_session_key(const uint32_t* d) const
    {
        uint32_t a, b, c;
        a = b = c = SMB_KEY_HASH_HARDENER;
        a += d[0]; b += d[1];  c += d[2];  mix(a, b, c);
        a += d[3]; b += d[4];  c += d[5];  mix(a, b, c);
        a += d[6]; b += d[7];  c += d[8];  mix(a, b, c);
        a += d[9]; b += d[10]; c += d[11]; finalize(a, b, c);
        return c;
    }

    size_t do_hash_message_key(const uint32_t* d) const
    {
        uint32_t a, b, c;
        a = b = c = SMB_KEY_HASH_HARDENER;
        a += d[0]; b += d[1]; c += d[2]; mix(a, b, c);
        finalize(a, b, c);
        return c;
    }

    inline uint32_t rot(uint32_t x, unsigned k) const
    { return (x << k) | (x >> (32 - k)); }

    inline void mix(uint32_t& a, uint32_t& b, uint32_t& c) const
    {
        a -= c; a ^= rot(c, 4); c += b;
        b -= a; b ^= rot(a, 6); a += c;
        c -= b; c ^= rot(b, 8); b += a;
        a -= c; a ^= rot(c,16); c += b;
        b -= a; b ^= rot(a,19); a += c;
        c -= b; c ^= rot(b, 4); b += a;
    }

    inline void finalize(uint32_t& a, uint32_t& b, uint32_t& c) const
    {
        c ^= b; c -= rot(b,14);
        a ^= c; a -= rot(c,11);
        b ^= a; b -= rot(a,25);
        c ^= b; c -= rot(b,16);
        a ^= c; a -= rot(c,4);
        b ^= a; b -= rot(a,14);
        c ^= b; c -= rot(b,24);
    }
};

uint32_t get_smb2_flow_key(const snort::FlowKey*);

class Dce2Smb2SessionData : public Dce2SmbSessionData
{
public:
    Dce2Smb2SessionData() = delete;
    Dce2Smb2SessionData(const snort::Packet*, const dce2SmbProtoConf* proto);
    ~Dce2Smb2SessionData() override;
    void process() override;
    void remove_session(uint64_t, bool = false);
    void handle_retransmit(FilePosition, FileVerdict) override { }
    void reset_matching_tcp_file_tracker(Dce2Smb2FileTrackerPtr);
    void set_reassembled_data(uint8_t*, uint16_t) override;
    uint32_t get_flow_key() { return flow_key; }
    void set_tcp_file_tracker(Dce2Smb2FileTrackerPtr file_tracker)
    {
        std::lock_guard<std::mutex> guard(session_data_mutex);
        tcp_file_tracker = file_tracker;
    }

    Dce2Smb2FileTrackerPtr get_tcp_file_tracker()
    {
        return tcp_file_tracker;
    }

    Dce2Smb2SessionTrackerPtr find_session(uint64_t);

private:
    void process_command(const Smb2Hdr*, const uint8_t*);
    Smb2SessionKey get_session_key(uint64_t);
    Dce2Smb2SessionTrackerPtr create_session(uint64_t);

    Dce2Smb2FileTrackerPtr tcp_file_tracker;
    uint32_t flow_key;
    Dce2Smb2SessionTrackerMap connected_sessions;
    std::mutex session_data_mutex;
    std::mutex tcp_file_tracker_mutex;
};

using Dce2Smb2SessionDataMap =
    std::unordered_map<uint32_t, Dce2Smb2SessionData*, std::hash<uint32_t> >;

#endif  /* _DCE_SMB2_H_ */

