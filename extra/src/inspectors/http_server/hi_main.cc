//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/**
**  @file       hi_main.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file wraps the HttpInspect functionality for Snort
**              and starts the HttpInspect flow.
**
**
**  The file takes a Packet structure from the Snort IDS to start the
**  HttpInspect flow.  This also uses the Stream Interface Module which
**  is also Snort-centric.  Mainly, just a wrapper to HttpInspect
**  functionality, but a key part to starting the basic flow.
**
**  The main bulk of this file is taken up with user configuration and
**  parsing.  The reason this is so large is because HttpInspect takes
**  very detailed configuration parameters for each specified server.
**  Hopefully every web server that is out there can be emulated
**  with these configuration options.
**
**  The main functions of note are:
**    - HttpInspectSnortConf::this is the configuration portion
**    - HttpInspect::this is the actual inspection flow
**
**  NOTES:
**
**  - 2.11.03:  Initial Development.  DJR
**  - 2.4.05:   Added tab_uri_delimiter config option.  AJM.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hi_main.h"

#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "file_api/file_flows.h"
#include "log/messages.h"
#include "log/unified2.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "search_engines/search_tool.h"
#include "stream/stream.h"
#include "utils/sfsnprintfappend.h"

#include "hi_ad.h"
#include "hi_include.h"
#include "hi_mi.h"
#include "hi_norm.h"
#include "hi_return_codes.h"
#include "hi_si.h"

const HiSearchToken hi_patterns[] =
{
    { "<SCRIPT",         7,  HI_JAVASCRIPT },
    { NULL,              0, 0 }
};

const HiSearchToken html_patterns[] =
{
    { "JAVASCRIPT",      10, HTML_JS },
    { "ECMASCRIPT",      10, HTML_EMA },
    { "VBSCRIPT",         8, HTML_VB },
    { NULL,               0, 0 }
};

SearchTool* hi_javascript_search_mpse = nullptr;
SearchTool* hi_htmltype_search_mpse = nullptr;

static uint32_t xtra_trueip_id;
static uint32_t xtra_uri_id;
static uint32_t xtra_hname_id;
static uint32_t xtra_gzip_id;
static uint32_t xtra_jsnorm_id;

HISearch hi_js_search[HI_LAST];
HISearch hi_html_search[HTML_LAST];

THREAD_LOCAL const HISearch* hi_current_search = NULL;
THREAD_LOCAL HISearchInfo hi_search_info;

THREAD_LOCAL HIStats hi_stats;

THREAD_LOCAL uint32_t http_mask;
THREAD_LOCAL HttpBuffer http_buffer[HTTP_BUFFER_MAX];
THREAD_LOCAL DataBuffer HttpDecodeBuf;

typedef enum
{
    CONFIG_MAX_SPACES = 0,
    CONFIG_MAX_JS_WS
} SpaceType;

unsigned HttpFlowData::flow_id = 0;

void HttpFlowData::init()
{
    flow_id = FlowData::get_flow_id();
}

HttpFlowData::HttpFlowData() : FlowData(flow_id)
{
    memset(&session, 0, sizeof(session));
    session.utf_state = new UtfDecodeSession();
}

HttpFlowData::~HttpFlowData()
{
    FreeHttpSessionData(&session);
}

HttpSessionData* SetNewHttpSessionData(Packet* p, void*)
{
    HttpFlowData* fd = new HttpFlowData;
    p->flow->set_flow_data(fd);
    return &fd->session;
}

static HttpSessionData* get_session_data(Flow* flow)
{
    HttpFlowData* fd = (HttpFlowData*)flow->get_flow_data(HttpFlowData::flow_id);
    return fd ? &fd->session : NULL;
}

void HttpInspectRegisterXtraDataFuncs()
{
    xtra_trueip_id = Stream::reg_xtra_data_cb(GetHttpTrueIP);
    xtra_uri_id = Stream::reg_xtra_data_cb(GetHttpUriData);
    xtra_hname_id = Stream::reg_xtra_data_cb(GetHttpHostnameData);
    xtra_gzip_id = Stream::reg_xtra_data_cb(GetHttpGzipData);
    xtra_jsnorm_id = Stream::reg_xtra_data_cb(GetHttpJSNormData);
}

static void PrintFileDecompOpt(HTTPINSPECT_CONF* ServerConf)
{
    LogMessage("      Decompress response files: %s %s %s\n",
        ((ServerConf->file_decomp_modes & FILE_SWF_ZLIB_BIT) != 0) ? "SWF-ZLIB" : "",
        ((ServerConf->file_decomp_modes & FILE_SWF_LZMA_BIT) != 0) ? "SWF-LZMA" : "",
        ((ServerConf->file_decomp_modes & FILE_PDF_DEFL_BIT) != 0) ? "PDF-DEFL" : "");
}

static int PrintConfOpt(HTTPINSPECT_CONF_OPT* ConfOpt, const char* Option)
{
    if (!ConfOpt || !Option)
    {
        return HI_INVALID_ARG;
    }

    if (ConfOpt->on)
        LogMessage("      %s: ON\n", Option);
    else
        LogMessage("      %s: OFF\n", Option);

    return 0;
}

int PrintServerConf(HTTPINSPECT_CONF* ServerConf)
{
    char buf[STD_BUF+1];
    int iCtr;
    int iChar = 0;
    PROFILES prof;

    if (!ServerConf)
    {
        return HI_INVALID_ARG;
    }

    prof = ServerConf->profile;
    LogMessage("      Server profile: %s\n",
        prof==HI_DEFAULT ? "Default" :
        prof==HI_APACHE ? "Apache" :
        prof==HI_IIS ? "IIS" :
        prof==HI_IIS4 ? "IIS4" : "IIS5");

    LogMessage("      Server Flow Depth: %d\n", ServerConf->server_flow_depth);
    LogMessage("      Client Flow Depth: %d\n", ServerConf->client_flow_depth);
    LogMessage("      Max Chunk Length: %d\n", ServerConf->chunk_length);
    if (ServerConf->small_chunk_length.size > 0)
        LogMessage("      Small Chunk Length Evasion: chunk size <= %u, threshold >= %u times\n",
            ServerConf->small_chunk_length.size, ServerConf->small_chunk_length.num);
    LogMessage("      Max Header Field Length: %d\n", ServerConf->max_hdr_len);
    LogMessage("      Max Number Header Fields: %d\n", ServerConf->max_headers);
    LogMessage("      Max Number of WhiteSpaces allowed with header folding: %d\n",
        ServerConf->max_spaces);
    LogMessage("      Inspect Pipeline Requests: %s\n",
        ServerConf->no_pipeline ? "NO" : "YES");
    LogMessage("      URI Discovery Strict Mode: %s\n",
        ServerConf->non_strict ? "NO" : "YES");
    LogMessage("      Allow Proxy Usage: %s\n",
        ServerConf->allow_proxy ? "YES" : "NO");
    LogMessage("      Oversize Dir Length: %d\n",
        ServerConf->long_dir);
    LogMessage("      Only inspect URI: %s\n",
        ServerConf->uri_only ? "YES" : "NO");
    LogMessage("      Normalize HTTP Headers: %s\n",
        ServerConf->normalize_headers ? "YES" : "NO");
    LogMessage("      Inspect HTTP Cookies: %s\n",
        ServerConf->enable_cookie ? "YES" : "NO");
    LogMessage("      Inspect HTTP Responses: %s\n",
        ServerConf->inspect_response ? "YES" : "NO");
    LogMessage("      Unlimited decompression of gzip data from responses: %s\n",
        ServerConf->unlimited_decompress ? "YES" : "NO");
    LogMessage("      Normalize Javascripts in HTTP Responses: %s\n",
        ServerConf->normalize_javascript ? "YES" : "NO");
    if (ServerConf->normalize_javascript)
    {
        if (ServerConf->max_js_ws)
            LogMessage(
                "      Max Number of WhiteSpaces allowed with Javascript Obfuscation in HTTP responses: %d\n",
                ServerConf->max_js_ws);
    }
    LogMessage("      Normalize HTTP Cookies: %s\n",
        ServerConf->normalize_cookies ? "YES" : "NO");
    LogMessage("      Enable XFF and True Client IP: %s\n",
        ServerConf->enable_xff ? "YES"  :  "NO");
    LogMessage("      Extended ASCII code support in URI: %s\n",
        ServerConf->extended_ascii_uri ? "YES" : "NO");
    LogMessage("      Log HTTP URI data: %s\n",
        ServerConf->log_uri ? "YES"  :  "NO");
    LogMessage("      Log HTTP Hostname data: %s\n",
        ServerConf->log_hostname ? "YES"  :  "NO");
    LogMessage("      Extract Gzip from responses: %s\n",
        ServerConf->extract_gzip ? "YES" : "NO");
    PrintFileDecompOpt(ServerConf);

    PrintConfOpt(&ServerConf->ascii, "Ascii");
    PrintConfOpt(&ServerConf->double_decoding, "Double Decoding");
    PrintConfOpt(&ServerConf->u_encoding, "%U Encoding");
    PrintConfOpt(&ServerConf->bare_byte, "Bare Byte");
    PrintConfOpt(&ServerConf->utf_8, "UTF 8");
    PrintConfOpt(&ServerConf->iis_unicode, "IIS Unicode");
    PrintConfOpt(&ServerConf->multiple_slash, "Multiple Slash");
    PrintConfOpt(&ServerConf->iis_backslash, "IIS Backslash");
    PrintConfOpt(&ServerConf->directory, "Directory Traversal");
    PrintConfOpt(&ServerConf->webroot, "Web Root Traversal");
    PrintConfOpt(&ServerConf->apache_whitespace, "Apache WhiteSpace");
    PrintConfOpt(&ServerConf->iis_delimiter, "IIS Delimiter");

    if (ServerConf->iis_unicode_map_filename)
    {
        LogMessage("      IIS Unicode Map Filename: %s\n",
            ServerConf->iis_unicode_map_filename);
        LogMessage("      IIS Unicode Map Codepage: %d\n",
            ServerConf->iis_unicode_codepage);
    }
    else if (ServerConf->iis_unicode_map)
    {
        LogMessage("      IIS Unicode Map: "
            "GLOBAL IIS UNICODE MAP CONFIG\n");
    }
    else
    {
        LogMessage("      IIS Unicode Map:  NOT CONFIGURED\n");
    }

    /*
    **  Print out the non-rfc chars
    */
    memset(buf, 0, STD_BUF+1);
    SnortSnprintf(buf, STD_BUF + 1, "      Non-RFC Compliant Characters: ");
    for (iCtr = 0; iCtr < 256; iCtr++)
    {
        if (ServerConf->non_rfc_chars[iCtr])
        {
            sfsnprintfappend(buf, STD_BUF, "0x%.2x ", (u_char)iCtr);
            iChar = 1;
        }
    }

    if (!iChar)
    {
        sfsnprintfappend(buf, STD_BUF, "NONE");
    }

    LogMessage("%s\n", buf);

    /*
    **  Print out the whitespace chars
    */
    iChar = 0;
    memset(buf, 0, STD_BUF+1);
    SnortSnprintf(buf, STD_BUF + 1, "      Whitespace Characters: ");
    for (iCtr = 0; iCtr < 256; iCtr++)
    {
        if (ServerConf->whitespace[iCtr])
        {
            sfsnprintfappend(buf, STD_BUF, "0x%.2x ", (u_char)iCtr);
            iChar = 1;
        }
    }

    if (!iChar)
    {
        sfsnprintfappend(buf, STD_BUF, "NONE");
    }

    LogMessage("%s\n", buf);

    return 0;
}

int PrintGlobalConf(HTTPINSPECT_GLOBAL_CONF* GlobalConf)
{
    LogMessage("HttpInspect Config:\n");
    LogMessage("    GLOBAL CONFIG\n");

    LogMessage("      Detect Proxy Usage:       %s\n",
        GlobalConf->proxy_alert ? "YES" : "NO");
    LogMessage("      IIS Unicode Map Filename: %s\n",
        GlobalConf->iis_unicode_map_filename);
    LogMessage("      IIS Unicode Map Codepage: %d\n",
        GlobalConf->iis_unicode_codepage);
    LogMessage("      Memcap used for logging URI and Hostname: %u\n",
        GlobalConf->memcap);
    LogMessage("      Max Gzip Memory: %d\n",
        GlobalConf->max_gzip_mem);
    LogMessage("      Max Gzip sessions: %d\n",
        GlobalConf->max_gzip_sessions);
    LogMessage("      Gzip Compress Depth: %d\n",
        GlobalConf->compr_depth);
    LogMessage("      Gzip Decompress Depth: %d\n",
        GlobalConf->decompr_depth);

    return 0;
}

static inline int SetSiInput(HI_SI_INPUT* SiInput, Packet* p)
{
    SiInput->sip.set(*p->ptrs.ip_api.get_src());
    SiInput->dip.set(*p->ptrs.ip_api.get_dst());
    SiInput->sport = p->ptrs.sp;
    SiInput->dport = p->ptrs.dp;

    /*
    **  We now set the packet direction
    */
    if (p->flow && Stream::is_midstream(p->flow))
    {
        SiInput->pdir = HI_SI_NO_MODE;
    }
    else if (p->is_from_server())
    {
        SiInput->pdir = HI_SI_SERVER_MODE;
    }
    else if (p->is_from_client())
    {
        SiInput->pdir = HI_SI_CLIENT_MODE;
    }
    else
    {
        SiInput->pdir = HI_SI_NO_MODE;
    }

    return HI_SUCCESS;
}

static inline void ApplyClientFlowDepth(Packet* p, int flow_depth)
{
    switch (flow_depth)
    {
    case -1:
        // Inspect none of the client if there is normalized/extracted
        // URI/Method/Header/Body data */
        SetDetectLimit(p, 0);
        break;

    case 0:
        // Inspect all of the client, even if there is normalized/extracted
        // URI/Method/Header/Body data */
        /* XXX: HUGE performance hit here */
        SetDetectLimit(p, p->dsize);
        break;

    default:
        // Limit inspection of the client, even if there is normalized/extracted
        // URI/Method/Header/Body data */
        /* XXX: Potential performance hit here */
        if (flow_depth < p->dsize)
        {
            SetDetectLimit(p, flow_depth);
        }
        else
        {
            SetDetectLimit(p, p->dsize);
        }
        break;
    }
}

static inline FilePosition getFilePoistion(Packet* p)
{
    FilePosition position = SNORT_FILE_POSITION_UNKNOWN;

    if (p->is_full_pdu())
        position = SNORT_FILE_FULL;
    else if (p->is_pdu_start())
        position = SNORT_FILE_START;
    else if (p->packet_flags & PKT_PDU_TAIL)
        position = SNORT_FILE_END;
    else if (get_file_processed_size(p->flow))
        position = SNORT_FILE_MIDDLE;

    return position;
}

// FIXIT-P extra data masks should only be updated as extra data changes state
// eg just once when captured; this function is called on every packet and
// repeatedly sets the flags on session
static inline void HttpLogFuncs(
    HttpSessionData* hsd, Packet* p, int iCallDetect)
{
    if (!hsd)
        return;

    /* for pipelined HTTP requests */
    if ( !iCallDetect )
        Stream::clear_extra_data(p->flow, p, 0);

    if (hsd->true_ip)
    {
        if (!(p->packet_flags & PKT_STREAM_INSERT) && !(p->packet_flags & PKT_REBUILT_STREAM))
            SetExtraData(p, xtra_trueip_id);
        else
            Stream::set_extra_data(p->flow, p, xtra_trueip_id);
    }

    if (hsd->log_flags & HTTP_LOG_URI)
    {
        Stream::set_extra_data(p->flow, p, xtra_uri_id);
    }

    if (hsd->log_flags & HTTP_LOG_HOSTNAME)
    {
        Stream::set_extra_data(p->flow, p, xtra_hname_id);
    }

    if (hsd->log_flags & HTTP_LOG_JSNORM_DATA)
    {
        SetExtraData(p, xtra_jsnorm_id);
    }
    if (hsd->log_flags & HTTP_LOG_GZIP_DATA)
    {
        SetExtraData(p, xtra_gzip_id);
    }
}

static inline void setFileName(Packet* p)
{
    uint8_t* buf = nullptr;
    uint32_t len = 0;
    uint32_t type = 0;
    GetHttpUriData(p->flow, &buf, &len, &type);

    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);

    if (file_flows)
        file_flows->set_file_name (buf, len);
}

static inline size_t getFileIndex(Flow* flow)
{
    static std::hash<std::string> hash_fn;
    uint8_t* buf = nullptr;
    uint32_t len = 0;
    uint32_t type = 0;

    GetHttpUriData(flow, &buf, &len, &type);

    if (!len or !buf)
        return 0;

    std::string str = std::string((const char*)buf,len);
    return (hash_fn(str));
}

/*
**  NAME
**    HttpInspectMain::
*/
/**
**  This function calls the HttpInspect function that processes an HTTP
**  session.
**
**  We need to instantiate a pointer for the HI_SESSION that HttpInspect
**  fills in.  Right now stateless processing fills in this session, which
**  we then normalize, and eventually detect.  We'll have to handle
**  separately the normalization events, etc.
**
**  This function is where we can see from the highest level what the
**  HttpInspect flow looks like.
**
**  @param GlobalConf pointer to the global configuration
**  @param p          pointer to the Packet structure
**
**  @return integer
**
**  @retval  0 function successful
**  @retval <0 fatal error
**  @retval >0 non-fatal error
*/
int HttpInspectMain(HTTPINSPECT_CONF* conf, Packet* p)
{
    HI_SESSION* session;
    HI_SI_INPUT SiInput;
    int iInspectMode = 0;
    int iRet;
    int iCallDetect = 1;
    HttpSessionData* hsd = NULL;

    hi_stats.total++;

    /*
    **  Set up the HI_SI_INPUT pointer.  This is what the session_inspection()
    **  routines use to determine client and server traffic.  Plus, this makes
    **  the HttpInspect library very independent from snort.
    */
    SetSiInput(&SiInput, p);

    /*
    **  HTTPINSPECT PACKET FLOW::
    **
    **  session Inspection Module::
    **    The session Inspection Module retrieves the appropriate server
    **    configuration for sessions, and takes care of the stateless
    **    vs. stateful processing in order to do this.  Once this module
    **    does it's magic, we're ready for the primetime.
    **
    **  HTTP Inspection Module::
    **    This isn't really a module in HttpInspect, but more of a helper
    **    function that sends the data to the appropriate inspection
    **    routine (client, server, anomalous server detection).
    **
    **  HTTP Normalization Module::
    **    This is where we normalize the data from the HTTP Inspection
    **    Module.  The Normalization module handles what type of normalization
    **    to do (client, server).
    **
    **  HTTP Detection Module::
    **    This isn't being used in the first iteration of HttpInspect, but
    **    all the HTTP detection components of signatures will be.
    **
    **  HTTP Event Output Module::
    **    The Event Ouput Module handles any events that have been logged
    **    in the inspection, normalization, or detection phases.
    */

    /*
    **  session Inspection Module::
    */
    iRet = hi_si_session_inspection(conf, &session, &SiInput, &iInspectMode, p);
    if (iRet)
        return iRet;

    /* If no mode then we just look for anomalous servers if configured
     * to do so and get out of here */
    if (iInspectMode == HI_SI_NO_MODE)
    {
        /* Let's look for rogue HTTP servers and stuff */
        if (conf->global->anomalous_servers && (p->dsize > 5))
        {
            iRet = hi_server_anomaly_detection(session, p->data, p->dsize);
            if (iRet)
                return iRet;
        }

        return 0;
    }

    hsd = get_session_data(p->flow);

    if ( (p->packet_flags & PKT_STREAM_INSERT) && !p->is_full_pdu() )
    {
        int flow_depth;

        if ( iInspectMode == HI_SI_CLIENT_MODE )
        {
            flow_depth = session->server_conf->client_flow_depth;
            ApplyClientFlowDepth(p, flow_depth);
        }
        else
        {
            ApplyFlowDepth(session->server_conf, p, hsd, 0, 0, GET_PKT_SEQ(p));
        }

        p->packet_flags |= PKT_HTTP_DECODE;

        if ( p->alt_dsize == 0 )
        {
            DetectionEngine::disable_content(p);
            return 0;
        }
        {
            ProfileExclude exclude(hiPerfStats);
            get_data_bus().publish(PACKET_EVENT, p);
        }

        return 0;
    }

    if (hsd == NULL)
        hsd = SetNewHttpSessionData(p, (void*)session);
    else
    {
        /* Gzip data should not be logged with all the packets of the session.*/
        hsd->log_flags &= ~HTTP_LOG_GZIP_DATA;
        hsd->log_flags &= ~HTTP_LOG_JSNORM_DATA;
    }

    /*
    **  HTTP Inspection Module::
    **
    **  This is where we do the client/server inspection and find the
    **  various HTTP protocol fields.  We then normalize these fields and
    **  call the detection engine.
    **
    **  The reason for the loop is for pipelined requests.  Doing pipelined
    **  requests in this way doesn't require any memory or tracking overhead.
    **  Instead, we just process each request linearly.
    */
    do
    {
        /*
        **  INIT:
        **  We set this equal to zero (again) because of the pipelining
        **  requests.  We don't want to bail before we get to setting the
        **  URI, so we make sure here that this can't happen.
        */
        SetHttpDecode(0);
        ClearHttpBuffers();

        iRet = hi_mi_mode_inspection(session, iInspectMode, p, hsd);
        if (iRet)
        {
            if (hsd)
            {
                if (hsd->mime_ssn)
                {
                    hsd->mime_ssn->process_mime_data(p->flow, p->data, p->dsize, 1,
                        SNORT_FILE_POSITION_UNKNOWN);
                }
                else if (get_file_processed_size(p->flow) >0)
                {
                    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
                    file_flows->file_process((uint8_t*)p->data, p->dsize,
                        getFilePoistion(p), true);
                }
            }
            return iRet;
        }

        iRet = hi_normalization(session, iInspectMode, hsd);
        if (iRet)
        {
            return iRet;
        }

        HttpLogFuncs(hsd, p, iCallDetect);

        /*
        **  Let's setup the pointers for the detection engine, and
        **  then go for it.
        */
        if ( iInspectMode == HI_SI_CLIENT_MODE )
        {
            const HttpBuffer* hb;
            ClearHttpBuffers();  // FIXIT-P needed here and right above??

            if ( session->client.request.uri_norm )
            {
                SetHttpBuffer(
                    HTTP_BUFFER_URI,
                    session->client.request.uri_norm,
                    session->client.request.uri_norm_size,
                    session->client.request.uri_encode_type);

                SetHttpBuffer(
                    HTTP_BUFFER_RAW_URI,
                    session->client.request.uri,
                    session->client.request.uri_size);

                p->packet_flags |= PKT_HTTP_DECODE;

                get_data_bus().publish(
                    "http_uri", session->client.request.uri_norm,
                    session->client.request.uri_norm_size, p->flow);
            }
            else if ( session->client.request.uri )
            {
                SetHttpBuffer(
                    HTTP_BUFFER_URI,
                    session->client.request.uri,
                    session->client.request.uri_size,
                    session->client.request.uri_encode_type);

                SetHttpBuffer(
                    HTTP_BUFFER_RAW_URI,
                    session->client.request.uri,
                    session->client.request.uri_size);

                p->packet_flags |= PKT_HTTP_DECODE;

                get_data_bus().publish(
                    "http_raw_uri", session->client.request.uri,
                    session->client.request.uri_size, p->flow);
            }

            if ( session->client.request.header_norm ||
                session->client.request.header_raw )
            {
                if ( session->client.request.header_norm )
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_HEADER,
                        session->client.request.header_norm,
                        session->client.request.header_norm_size,
                        session->client.request.header_encode_type);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_HEADER,
                        session->client.request.header_raw,
                        session->client.request.header_raw_size);

                    p->packet_flags |= PKT_HTTP_DECODE;
                }
                else
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_HEADER,
                        session->client.request.header_raw,
                        session->client.request.header_raw_size,
                        session->client.request.header_encode_type);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_HEADER,
                        session->client.request.header_raw,
                        session->client.request.header_raw_size);

                    p->packet_flags |= PKT_HTTP_DECODE;
                }
            }

            if (session->client.request.method & (HI_POST_METHOD | HI_GET_METHOD))
            {
                if (session->client.request.post_raw)
                {
                    uint8_t* start = (uint8_t*)(session->client.request.content_type);

                    if ( hsd && start )
                    {
                        /* mime parsing
                         * mime boundary should be processed before this
                         */

                        if (!hsd->mime_ssn)
                        {
                            hsd->mime_ssn = new MimeSession(conf->global->decode_conf,
                                &(conf->global->mime_conf));
                        }

                        hsd->mime_ssn->process_mime_data(p->flow, start,
                            session->client.request.post_raw +
                            session->client.request.post_raw_size - start, 1,
                            SNORT_FILE_POSITION_UNKNOWN);
                    }
                    else
                    {
                        FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
                        if (file_flows && file_flows->file_process(
                            (uint8_t*)session->client.request.post_raw,
                            (uint16_t)session->client.request.post_raw_size,
                            getFilePoistion(p), true))
                        {
                            setFileName(p);
                        }
                    }

                    if (session->server_conf->post_depth > -1)
                    {
                        if (session->server_conf->post_depth &&
                            ((int)session->client.request.post_raw_size >
                            session->server_conf->post_depth))
                        {
                            session->client.request.post_raw_size =
                                session->server_conf->post_depth;
                        }
                        SetHttpBuffer(
                            HTTP_BUFFER_CLIENT_BODY,
                            session->client.request.post_raw,
                            session->client.request.post_raw_size,
                            session->client.request.post_encode_type);

                        p->packet_flags |= PKT_HTTP_DECODE;
                    }
                }
            }
            else if (hsd)
            {
                if (hsd->mime_ssn)
                {
                    hsd->mime_ssn->process_mime_data(p->flow, p->data, p->dsize, 1,
                        SNORT_FILE_POSITION_UNKNOWN);
                }
                else if (get_file_processed_size(p->flow) >0)
                {
                    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
                    file_flows->file_process((uint8_t*)p->data, p->dsize,
                        getFilePoistion(p), true);
                }
            }

            if ( session->client.request.method_raw )
            {
                SetHttpBuffer(
                    HTTP_BUFFER_METHOD,
                    session->client.request.method_raw,
                    session->client.request.method_size);

                p->packet_flags |= PKT_HTTP_DECODE;
            }

            if ( session->client.request.cookie_norm ||
                session->client.request.cookie.cookie )
            {
                if ( session->client.request.cookie_norm )
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_COOKIE,
                        session->client.request.cookie_norm,
                        session->client.request.cookie_norm_size,
                        session->client.request.cookie_encode_type);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_COOKIE,
                        session->client.request.cookie.cookie,
                        session->client.request.cookie.cookie_end -
                        session->client.request.cookie.cookie);

                    p->packet_flags |= PKT_HTTP_DECODE;
                }
                else
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_COOKIE,
                        session->client.request.cookie.cookie,
                        session->client.request.cookie.cookie_end -
                        session->client.request.cookie.cookie,
                        session->client.request.cookie_encode_type);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_COOKIE,
                        session->client.request.cookie.cookie,
                        session->client.request.cookie.cookie_end -
                        session->client.request.cookie.cookie);

                    p->packet_flags |= PKT_HTTP_DECODE;
                }
            }
            else if ( !session->server_conf->enable_cookie &&
                (hb = GetHttpBuffer(HTTP_BUFFER_HEADER)) )
            {
                SetHttpBuffer(
                    HTTP_BUFFER_COOKIE, hb->buf, hb->length, hb->encode_type);

                hb = GetHttpBuffer(HTTP_BUFFER_RAW_HEADER);
                assert(hb);

                SetHttpBuffer(HTTP_BUFFER_RAW_COOKIE, hb->buf, hb->length);

                p->packet_flags |= PKT_HTTP_DECODE;
            }

            if ( IsLimitedDetect(p) )
            {
                ApplyClientFlowDepth(p, session->server_conf->client_flow_depth);

                if ( !GetHttpBufferMask() && (p->alt_dsize == 0)  )
                {
                    DetectionEngine::disable_content(p);
                    return 0;
                }
            }
        }
        else   /* Server mode */
        {
            const HttpBuffer* hb;

            /*
            **  We check here to see whether this was a server response
            **  header or not.  If the header size is 0 then, we know that this
            **  is not the header and don't do any detection.
            */
            if ( !(session->server_conf->inspect_response) &&
                IsLimitedDetect(p) && !p->alt_dsize )
            {
                DetectionEngine::disable_content(p);
                return 0;
            }
            ClearHttpBuffers();

            if ( session->server.response.header_norm ||
                session->server.response.header_raw )
            {
                if ( session->server.response.header_norm )
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_HEADER,
                        session->server.response.header_norm,
                        session->server.response.header_norm_size,
                        session->server.response.header_encode_type);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_HEADER,
                        session->server.response.header_raw,
                        session->server.response.header_raw_size);
                }
                else
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_HEADER,
                        session->server.response.header_raw,
                        session->server.response.header_raw_size);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_HEADER,
                        session->server.response.header_raw,
                        session->server.response.header_raw_size);
                }
            }

            if ( session->server.response.cookie_norm ||
                session->server.response.cookie.cookie )
            {
                if (session->server.response.cookie_norm )
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_COOKIE,
                        session->server.response.cookie_norm,
                        session->server.response.cookie_norm_size,
                        session->server.response.cookie_encode_type);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_COOKIE,
                        session->server.response.cookie.cookie,
                        session->server.response.cookie.cookie_end -
                        session->server.response.cookie.cookie);
                }
                else
                {
                    SetHttpBuffer(
                        HTTP_BUFFER_COOKIE,
                        session->server.response.cookie.cookie,
                        session->server.response.cookie.cookie_end -
                        session->server.response.cookie.cookie);

                    SetHttpBuffer(
                        HTTP_BUFFER_RAW_COOKIE,
                        session->server.response.cookie.cookie,
                        session->server.response.cookie.cookie_end -
                        session->server.response.cookie.cookie);
                }
            }
            else if ( !session->server_conf->enable_cookie &&
                (hb = GetHttpBuffer(HTTP_BUFFER_HEADER)) )
            {
                SetHttpBuffer(
                    HTTP_BUFFER_COOKIE, hb->buf, hb->length, hb->encode_type);

                hb = GetHttpBuffer(HTTP_BUFFER_RAW_HEADER);
                assert(hb);

                SetHttpBuffer(HTTP_BUFFER_RAW_COOKIE, hb->buf, hb->length);
            }

            if (session->server.response.status_code)
            {
                SetHttpBuffer(
                    HTTP_BUFFER_STAT_CODE,
                    session->server.response.status_code,
                    session->server.response.status_code_size);
            }

            if (session->server.response.status_msg)
            {
                SetHttpBuffer(
                    HTTP_BUFFER_STAT_MSG,
                    session->server.response.status_msg,
                    session->server.response.status_msg_size);
            }

            if (session->server.response.body_size > 0)
            {
                int detect_data_size = (int)session->server.response.body_size;

                /*body_size is included in the data_extracted*/
                if ((session->server_conf->server_flow_depth > 0) &&
                    (hsd->resp_state.data_extracted  < (session->server_conf->server_flow_depth +
                    (int)session->server.response.body_size)))
                {
                    /*flow_depth is smaller than data_extracted, need to subtract*/
                    if (session->server_conf->server_flow_depth < hsd->resp_state.data_extracted)
                        detect_data_size -= hsd->resp_state.data_extracted -
                            session->server_conf->server_flow_depth;
                }
                else if (session->server_conf->server_flow_depth)
                {
                    detect_data_size = 0;
                }

                /* Do we have a file decompression object? */
                if ( hsd->fd_state != 0 )
                {
                    fd_status_t Ret_Code;

                    uint16_t Data_Len;
                    const uint8_t* Data;

                    hsd->fd_state->Next_In = (uint8_t*)(Data = session->server.response.body);
                    hsd->fd_state->Avail_In = (Data_Len = (uint16_t)detect_data_size);

                    (void)File_Decomp_SetBuf(hsd->fd_state);

                    Ret_Code = File_Decomp(hsd->fd_state);

                    if ( Ret_Code == File_Decomp_DecompError )
                    {
                        session->server.response.body = Data;
                        session->server.response.body_size = Data_Len;

                        File_Decomp_Alert(hsd->fd_state, hsd->fd_state->Error_Event);
                        File_Decomp_StopFree(hsd->fd_state);
                        hsd->fd_state = NULL;
                    }
                    /* If we didn't find a Sig, then clear the File_Decomp state
                       and don't keep looking. */
                    else if ( Ret_Code == File_Decomp_NoSig )
                    {
                        File_Decomp_StopFree(hsd->fd_state);
                        hsd->fd_state = NULL;
                    }
                    else
                    {
                        session->server.response.body = hsd->fd_state->Buffer;
                        session->server.response.body_size = hsd->fd_state->Total_Out;
                    }

                    set_file_data((uint8_t*)session->server.response.body,
                        (uint16_t)session->server.response.body_size);
                }
                else
                {
                    set_file_data((uint8_t*)session->server.response.body,
                        (uint16_t)detect_data_size); 
                }

                FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
                if (p->has_paf_payload()
                    && file_flows &&  file_flows->file_process(
                    (uint8_t*)session->server.response.body,
                    (uint16_t)session->server.response.body_size,
                    getFilePoistion(p), false, getFileIndex(p->flow)))
                {
                    setFileName(p);
                }
            }

            if ( IsLimitedDetect(p) &&
                !GetHttpBufferMask() && (p->alt_dsize == 0)  )
            {
                DetectionEngine::disable_content(p);
                return 0;
            }
        }

        /*
        **  If we get here we either had a client or server request/response.
        **  We do the detection here, because we're starting a new paradigm
        **  about protocol decoders.
        **
        **  Protocol decoders are now their own detection engine, since we are
        **  going to be moving protocol field detection from the generic
        **  detection engine into the protocol module.  This idea scales much
        **  better than having all these Packet struct field checks in the
        **  main detection engine for each protocol field.
        */
        {
            Profile exclude(hiPerfStats);
            DetectionEngine::detect(p);
        }

        /*
        **  We set the global detection flag here so that if request pipelines
        **  fail, we don't do any detection.
        */
        iCallDetect = 0;
    }
    while (session->client.request.pipeline_req);

    if ( iCallDetect == 0 )
    {
        // DetectionEngine::detect called at least once from above pkt processing loop.
        DetectionEngine::disable_content(p);
    }

    return 0;
}

int HttpInspectInitializeGlobalConfig(HTTPINSPECT_GLOBAL_CONF* config)
{
    int iRet;

    if ( !config )
        return -1;

    iRet = hi_ui_config_init_global_conf(config);
    if (iRet)
        return iRet;

    iRet = hi_client_init();
    if (iRet)
        return iRet;

    return 0;
}

void FreeHttpSessionData(void* data)
{
    HttpSessionData* hsd = (HttpSessionData*)data;

    if (hsd->decomp_state != NULL)
    {
        inflateEnd(&(hsd->decomp_state->d_stream));
        snort_free(hsd->decomp_state);
    }

    if (hsd->log_state != NULL)
        snort_free(hsd->log_state);

    if (hsd->true_ip)
        delete hsd->true_ip;

    if (hsd->mime_ssn)
        delete hsd->mime_ssn;

    if (hsd->utf_state)
        delete hsd->utf_state;

    if ( hsd->fd_state != 0 )
    {
        File_Decomp_StopFree(hsd->fd_state);
        hsd->fd_state = NULL;                  // ...just for good measure
    }
}

int GetHttpTrueIP(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpSessionData* hsd = get_session_data(flow);

    if (!hsd->true_ip)
        return 0;

    if (hsd->true_ip->is_ip6())
    {
        *type = EVENT_INFO_XFF_IPV6;
        *len = sizeof(struct in6_addr); /*ipv6 address size in bytes*/
    }
    else
    {
        *type = EVENT_INFO_XFF_IPV4;
        *len = sizeof(struct in_addr); /*ipv4 address size in bytes*/
    }

    *buf = (uint8_t*) hsd->true_ip->get_ptr();
    return 1;
}

int IsGzipData(Flow* flow)
{
    HttpSessionData* hsd = NULL;

    if (flow == NULL)
        return -1;

    hsd = get_session_data(flow);

    if (hsd == NULL)
        return -1;

    DataPointer file_data;
    DetectionEngine::get_file_data(file_data);

    if ((hsd->log_flags & HTTP_LOG_GZIP_DATA) && (file_data.len > 0 ))
        return 0;
    else
        return -1;
}

int GetHttpGzipData(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    if (!IsGzipData(flow))
    {
        DataPointer file_data;
        DetectionEngine::get_file_data(file_data);

        *buf = (uint8_t*)file_data.data;
        *len = file_data.len;
        *type = EVENT_INFO_GZIP_DATA;
        return 1;
    }

    return 0;
}

int IsJSNormData(Flow* flow)
{
    HttpSessionData* hsd = NULL;

    if (flow == NULL)
        return -1;

    hsd = get_session_data(flow);

    if (hsd == NULL)
        return -1;

    DataPointer file_data;
    DetectionEngine::get_file_data(file_data);

    if ((hsd->log_flags & HTTP_LOG_JSNORM_DATA) && (file_data.len > 0 ))
        return 0;
    else
        return -1;
}

int GetHttpJSNormData(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    if (!IsJSNormData(flow))
    {
        DataPointer file_data;
        DetectionEngine::get_file_data(file_data);

        *buf = (uint8_t*)file_data.data;
        *len = file_data.len;
        *type = EVENT_INFO_JSNORM_DATA;
        return 1;
    }

    return 0;
}

int GetHttpUriData(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpSessionData* hsd = NULL;

    if (flow == NULL)
        return 0;

    hsd = get_session_data(flow);

    if (hsd == NULL)
        return 0;

    if (hsd->log_state && hsd->log_state->uri_bytes > 0)
    {
        *buf = hsd->log_state->uri_extracted;
        *len = hsd->log_state->uri_bytes;
        *type = EVENT_INFO_HTTP_URI;
        return 1;
    }

    return 0;
}

int GetHttpHostnameData(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpSessionData* hsd = NULL;

    if (flow == NULL)
        return 0;

    hsd = get_session_data(flow);

    if (hsd == NULL)
        return 0;

    if (hsd->log_state && hsd->log_state->hostname_bytes > 0)
    {
        *buf = hsd->log_state->hostname_extracted;
        *len = hsd->log_state->hostname_bytes;
        *type = EVENT_INFO_HTTP_HOSTNAME;
        return 1;
    }

    return 0;
}

void HI_SearchInit()
{
    const HiSearchToken* tmp;
    hi_javascript_search_mpse = new SearchTool();

    for (tmp = &hi_patterns[0]; tmp->name != NULL; tmp++)
    {
        hi_js_search[tmp->search_id].name = tmp->name;
        hi_js_search[tmp->search_id].name_len = tmp->name_len;
        hi_javascript_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    hi_javascript_search_mpse->prep();
    hi_htmltype_search_mpse = new SearchTool();

    for (tmp = &html_patterns[0]; tmp->name != NULL; tmp++)
    {
        hi_html_search[tmp->search_id].name = tmp->name;
        hi_html_search[tmp->search_id].name_len = tmp->name_len;
        hi_htmltype_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    hi_htmltype_search_mpse->prep();
}

void HI_SearchFree()
{
    if (hi_javascript_search_mpse != NULL)
        delete hi_javascript_search_mpse;

    if (hi_htmltype_search_mpse != NULL)
        delete hi_htmltype_search_mpse;
}

int HI_SearchStrFound(void* id, void*, int index, void*, void*)
{
    int search_id = (int)(uintptr_t)id;

    hi_search_info.id = search_id;
    hi_search_info.length = hi_current_search[search_id].name_len;
    hi_search_info.index = index - hi_search_info.length;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

