//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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
/*
 * Description:
 *
 * This file contains structures and functions for the
 * session Inspection Module.
 *
 * The session Inspection Module has several data structures that are
 * very important to the functionality of the module.  The two major
 * structures are the FTPP_SESSION and the FTPP_SI_INPUT.
 *
 * NOTES:
 * - 20.09.04:  Initial Development.  SAS
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 */
#ifndef FTPP_SI_H
#define FTPP_SI_H

#include "file_api/file_api.h"
#include "flow/flow.h"
#include "flow/flow_key.h"
#include "framework/counts.h"

#include "ftp_client.h"
#include "ftp_server.h"
#include "ftpp_ui_config.h"

/*
 * These are the defines for the different types of
 * inspection modes.  We have a server mode and a client mode.
 */
#define FTPP_SI_NO_MODE     0
#define FTPP_SI_CLIENT_MODE 1
#define FTPP_SI_SERVER_MODE 2

#define FTPP_SI_PROTO_UNKNOWN   0
#define FTPP_SI_PROTO_TELNET    1
#define FTPP_SI_PROTO_FTP       2
#define FTPP_SI_PROTO_FTP_DATA  3

#define FTPP_FILE_IGNORE    (-1)
#define FTPP_FILE_UNKNOWN    0

/* Macros for testing the type of FTP_TELNET_SESSION */
#define FTPP_SI_IS_PROTO(Ssn, Pro)      ((Ssn) && ((Ssn)->ft_ssn.proto == (Pro)))
#define PROTO_IS_FTP(ssn)               FTPP_SI_IS_PROTO(ssn, FTPP_SI_PROTO_FTP)
#define PROTO_IS_FTP_DATA(ssn)          FTPP_SI_IS_PROTO(ssn, FTPP_SI_PROTO_FTP_DATA)
#define PROTO_IS_TELNET(ssn)            FTPP_SI_IS_PROTO(ssn, FTPP_SI_PROTO_TELNET)

#define FTP_FLG_MALWARE  (1<<0)

typedef struct s_FTP_TELNET_SESSION
{
    int proto;
} FTP_TELNET_SESSION;

/*
 * The TELNET_SESSION structure contains the complete TELNET session.
 * This structure is the structure that is saved per session in the
 * Stream Interface Module.  This structure gets sent through the
 * detection engine process (Normalization, Detection).
 */
struct TELNET_SESSION
{
    FTP_TELNET_SESSION ft_ssn;

    /* The client configuration for this session if its FTP */
    TELNET_PROTO_CONF* telnet_conf;

    /* Number of consecutive are-you-there commands seen. */
    int consec_ayt;

    int encr_state;
};

class TelnetFlowData : public snort::FlowData
{
public:
    TelnetFlowData();
    ~TelnetFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    TELNET_SESSION session;
};

/*
 * These are the state values for determining the FTP data channel.
 */
#define NO_STATE                  0x00
#define LOST_STATE                0xFFFFFFFF

#define DATA_CHAN_PORT_CMD_ISSUED   0x01
#define DATA_CHAN_PORT_CMD_ACCEPT   0x02
#define DATA_CHAN_PASV_CMD_ISSUED   0x04
#define DATA_CHAN_PASV_CMD_ACCEPT   0x08
#define DATA_CHAN_XFER_CMD_ISSUED   0x10
#define DATA_CHAN_XFER_STARTED      0x20
#define DATA_CHAN_CLIENT_HELLO_SEEN 0x40
#define DATA_CHAN_REST_CMD_ISSUED   0x80

#define AUTH_TLS_CMD_ISSUED         0x01
#define AUTH_SSL_CMD_ISSUED         0x02
#define AUTH_UNKNOWN_CMD_ISSUED     0x04
#define AUTH_TLS_ENCRYPTED          0x08
#define AUTH_SSL_ENCRYPTED          0x10
#define AUTH_UNKNOWN_ENCRYPTED      0x20

/*
 * The FTP_SESSION structure contains the complete FTP session, both the
 * client and the server constructs.  This structure is the structure that
 * is saved per session in the Stream Interface Module.  This structure
 * gets sent through the detection engine process (Normalization,
 * Detection).
 */
struct FTP_SESSION
{
    FTP_TELNET_SESSION ft_ssn;

    /* The client construct contains all the info associated with a
     * client request. */
    FTP_CLIENT client;

    /* The server construct contains all the info associated with a
     * server response. */
    FTP_SERVER server;

    /* The client configuration for this session if its FTP */
    FTP_CLIENT_PROTO_CONF* client_conf;

    /* The server configuration for this session if its FTP */
    FTP_SERVER_PROTO_CONF* server_conf;

    /* The data channel info */
    int data_chan_state;
    int data_chan_index;
    int data_xfer_index;
    bool data_xfer_dir;
    snort::SfIp clientIP;
    uint16_t clientPort;
    snort::SfIp serverIP;
    uint16_t serverPort;

    /* A file is being transferred on ftp-data channel */
    char* filename;
    int file_xfer_info; /* -1: ignore, 0: unknown, >0: filename length */
    unsigned char flags;

    /* Command/data channel encryption */
    int encr_state;
    void *datassn;
};

void FTPFreesession(FTP_SESSION*);

class FtpFlowData : public snort::FlowData
{
public:
    FtpFlowData();
    ~FtpFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    FTP_SESSION session;
};

/* FTP-Data Transfer Modes */
enum
{
    FTPP_XFER_PASSIVE = 0,
    FTPP_XFER_ACTIVE  = 1
};

struct FTP_DATA_SESSION
{
    FTP_TELNET_SESSION ft_ssn;
    snort::FlowKey ftp_key;
    char* filename;
    int data_chan;
    int file_xfer_info;
    FilePosition position;
    bool direction;
    unsigned char mode;
    unsigned char packet_flags;
};

class FtpDataFlowData : public snort::FlowData
{
public:
    FtpDataFlowData(snort::Packet*);
    ~FtpDataFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

    void handle_expected(snort::Packet*) override;
    void handle_eof(snort::Packet*) override;

public:
    static unsigned inspector_id;
    FTP_DATA_SESSION session;
    bool eof_handled = false;
};

#define FTPDATA_FLG_REASSEMBLY_SET  (1<<0)
#define FTPDATA_FLG_FILENAME_SET    (1<<1)
#define FTPDATA_FLG_STOP            (1<<2)
#define FTPDATA_FLG_REST            (1<<3)
#define FTPDATA_FLG_FLUSH           (1<<4)

/*
 * The FTPP_SI_INPUT structure holds the information that the session
 * Inspection Module needs to determine the type of inspection mode
 * (client, server, neither) and to retrieve the appropriate server
 * configuration.
 *
 * The input is the source and destination IP addresses, and the
 * source and destination ports (since this should always be a
 * TCP packet).
 */
struct FTPP_SI_INPUT
{
    snort::SfIp sip;
    snort::SfIp dip;
    unsigned short sport;
    unsigned short dport;
    unsigned char pdir;
    unsigned char pproto;
};

int FTPGetPacketDir(snort::Packet*);

/* FTP-Data file processing */
FTP_DATA_SESSION* FTPDatasessionNew(snort::Packet* p);
void FTPDatasessionFree(void* p_ssn);

bool FTPDataDirection(snort::Packet* p, FTP_DATA_SESSION* ftpdata);

int TelnetsessionInspection(snort::Packet*, TELNET_PROTO_CONF*, TELNET_SESSION**,
    FTPP_SI_INPUT*, int* piInspectMode);

int FTPsessionInspection(snort::Packet*, FTP_SESSION**, FTPP_SI_INPUT*, int* piInspectMode);

int SetSiInput(FTPP_SI_INPUT*, snort::Packet*);

struct FtpStats
{
    PegCount total_packets;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

struct TelnetStats
{
    PegCount total_packets;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

extern THREAD_LOCAL FtpStats ftstats;
extern THREAD_LOCAL TelnetStats tnstats;

#endif

