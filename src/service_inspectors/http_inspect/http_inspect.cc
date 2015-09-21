//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file initializes HttpInspect as a Snort
**              preprocessor.
**
**  This file registers the HttpInspect initialization function,
**  adds the HttpInspect function into the preprocessor list, reads
**  the user configuration in the snort.conf file, and prints out
**  the configuration that is read.
**
**  In general, this file is a wrapper to HttpInspect functionality,
**  by interfacing with the Snort preprocessor functions.  The rest
**  of HttpInspect should be separate from the preprocessor hooks.
**
**  - 2.10.03:  Initial Development.  DJR
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "protocols/packet.h"
#include "main/snort_debug.h"
#include "parser/parser.h"
#include "decompress/file_decomp.h"
#include "time/profiler.h"
#include "detection/detection_util.h"
#include "stream/stream_api.h"
#include "target_based/snort_protocols.h"
#include "file_api/file_api.h"
#include "file_api/file_service.h"
#include "utils/kmap.h"
#include <mime/decode_base.h>
#include "utils/util.h"
#include "utils/xmalloc.h"
#include "framework/inspector.h"
#include "managers/inspector_manager.h"

#include "hi_client.h"
#include "hi_ui_config.h"
#include "hi_module.h"
#include "hi_norm.h"
#include "hi_main.h"
#include "hi_cmd_lookup.h"
#include "hi_stream_splitter.h"

int hex_lookup[256];
int valid_lookup[256];

// hiDetectPerfStats is not registered; it is used
// only to exclude detection from hiPerfStats
THREAD_LOCAL ProfileStats hiPerfStats;
THREAD_LOCAL ProfileStats hiDetectPerfStats;

const PegInfo peg_names[] =
{
    { "packets", "total packets processed" },
    { "gets", "GET requests" },
    { "posts", "POST requests" },

    { "request headers", "total requests" },
    { "response headers", "total responses" },
    { "request cookies", "requests with Cookie" },
    { "response cookies", "responses with Set-Cookie" },
    { "post params", "POST parameters extracted" },

    { "unicode", "unicode normalizations" },
    { "double unicode", "double unicode normalizations" },
    { "non-ascii", "non-ascii normalizations" },
    { "paths with ../", "directory traversal normalizations" },
    { "paths with //", "double slash normalizations" },
    { "paths with ./", "relative directory normalizations" },

    { "gzip packets", "packets with gzip compression" },
    { "compressed bytes", "total comparessed bytes processed" },
    { "decompressed bytes", "total bytes decompressed" },

    { nullptr, nullptr }
};

THREAD_LOCAL int hiDetectCalled = 0;

/*
** Prototypes
*/
static inline void InitLookupTables(void);
static void CheckGzipConfig(HTTPINSPECT_GLOBAL_CONF*);
static void CheckMemcap(HTTPINSPECT_GLOBAL_CONF*);

static void CheckGzipConfig(HTTPINSPECT_GLOBAL_CONF* pPolicyConfig)
{
    if (!pPolicyConfig->max_gzip_mem)
        pPolicyConfig->max_gzip_mem = DEFAULT_MAX_GZIP_MEM;

    if (!pPolicyConfig->compr_depth)
        pPolicyConfig->compr_depth = DEFAULT_COMP_DEPTH;

    if (!pPolicyConfig->decompr_depth)
        pPolicyConfig->decompr_depth = DEFAULT_DECOMP_DEPTH;

    pPolicyConfig->max_gzip_sessions =
        pPolicyConfig->max_gzip_mem / (sizeof(DECOMPRESS_STATE) + sizeof(fd_session_t));
}

static void CheckMemcap(HTTPINSPECT_GLOBAL_CONF* pPolicyConfig)
{
    if (!pPolicyConfig->memcap)
        pPolicyConfig->memcap = DEFAULT_HTTP_MEMCAP;
}

static void updateConfigFromFileProcessing(HTTPINSPECT_CONF* ServerConf)
{
    /*Either one is unlimited*/
    int64_t fileDepth = FileService::get_max_file_depth();

    /*Config file policy*/
    if (fileDepth > -1)
    {
        ServerConf->inspect_response = 1;
        ServerConf->unlimited_decompress = 1;
        ServerConf->extract_gzip = 1;
        ServerConf->log_uri = 1;
        ServerConf->global->mime_conf.log_filename = 1;
    }

    if (!fileDepth || (!ServerConf->server_flow_depth))
        ServerConf->server_extract_size = 0;
    else if (ServerConf->server_flow_depth > fileDepth)
        ServerConf->server_extract_size = ServerConf->server_flow_depth;
    else
        ServerConf->server_extract_size = fileDepth;

    if (!fileDepth || (!ServerConf->post_depth))
        ServerConf->post_extract_size = 0;
    else if (ServerConf->post_depth > fileDepth)
        ServerConf->post_extract_size = ServerConf->post_depth;
    else
        ServerConf->post_extract_size = fileDepth;
}

static int HttpInspectVerifyPolicy(SnortConfig*, HTTPINSPECT_CONF* pData)
{
    HttpInspectRegisterXtraDataFuncs();  // FIXIT-L must be done once

    updateConfigFromFileProcessing(pData);
    return 0;
}

typedef struct _HttpEncodeData
{
    HTTP_BUFFER http_type;
    int encode_type;
}HttpEncodeData;

static inline void InitLookupTables(void)
{
    int iNum;
    int iCtr;

    memset(hex_lookup, INVALID_HEX_VAL, sizeof(hex_lookup));
    memset(valid_lookup, INVALID_HEX_VAL, sizeof(valid_lookup));

    iNum = 0;
    for (iCtr = 48; iCtr < 58; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }

    /*
    * Set the upper case values.
    */
    iNum = 10;
    for (iCtr = 65; iCtr < 71; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }

    /*
     *  Set the lower case values.
     */
    iNum = 10;
    for (iCtr = 97; iCtr < 103; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

typedef InspectorData<HTTPINSPECT_GLOBAL_CONF> HttpData;

class HttpInspect : public Inspector
{
public:
    HttpInspect(HTTPINSPECT_CONF*);
    ~HttpInspect();

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new HttpSplitter(c2s); }

    void eval(Packet*) override;

    void clear(Packet*) override
    { ClearHttpBuffers(); }

    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;
    bool get_buf(unsigned, Packet*, InspectionBuffer&) override;

private:
    HTTPINSPECT_CONF* config;
    HttpData* global;
};

HttpInspect::HttpInspect(HTTPINSPECT_CONF* p)
{
    config = p;
    global = nullptr;
}

HttpInspect::~HttpInspect ()
{
    if ( config )
        delete config;

    if ( global )
        InspectorManager::release(global);
}

bool HttpInspect::get_buf(
    InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    switch ( ibt )
    {
    case InspectionBuffer::IBT_KEY:
        return get_buf(HTTP_BUFFER_URI, p, b);

    case InspectionBuffer::IBT_HEADER:
        return get_buf(HTTP_BUFFER_HEADER, p, b);

    case InspectionBuffer::IBT_BODY:
        return get_buf(HTTP_BUFFER_CLIENT_BODY, p, b);

    default:
        break;
    }
    return false;
}

bool HttpInspect::get_buf(unsigned id, Packet*, InspectionBuffer& b)
{
    const HttpBuffer* h = GetHttpBuffer((HTTP_BUFFER)id);

    if ( !h )
        return false;

    b.data = h->buf;
    b.len = h->length;
    return true;
}

bool HttpInspect::configure(SnortConfig* sc)
{
    global = (HttpData*)InspectorManager::acquire(GLOBAL_KEYWORD, sc);
    config->global = global->data;

    HttpInspectInitializeGlobalConfig(config->global);

    CheckGzipConfig(config->global);
    CheckMemcap(config->global);

    config->global->decode_conf->sync_all_depths();

    if (config->global->decode_conf->get_file_depth() > -1)
        config->global->mime_conf.log_filename = 1;

    return !HttpInspectVerifyPolicy(sc, config);
}

void HttpInspect::show(SnortConfig*)
{
    PrintGlobalConf(config->global);

    LogMessage("    DEFAULT SERVER CONFIG:\n");
    PrintServerConf(config);
}

void HttpInspect::eval(Packet* p)
{
    PROFILE_VARS;

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    MODULE_PROFILE_START(hiPerfStats);
    hi_clear_events();

    HttpInspectMain(config, p);

    hi_queue_events();
    ClearHttpBuffers();

    /* XXX:
     * NOTE: this includes the HTTPInspect directly
     * calling the detection engine -
     * to get the true HTTPInspect only stats, have another
     * var inside HttpInspectMain that tracks the time
     * spent in snort_detect().
     * Subtract the ticks from this if iCallDetect == 0
     */
    MODULE_PROFILE_END(hiPerfStats);
#ifdef PERF_PROFILING
    if (hiDetectCalled)
    {
        hiPerfStats.ticks -= hiDetectPerfStats.ticks;
        /* And Reset ticks to 0 */
        hiDetectPerfStats.ticks = 0;
        hiDetectCalled = 0;
    }
#endif
}

//-------------------------------------------------------------------------
// api stuff
// hg_* -> http_global (data)
//-------------------------------------------------------------------------

static Module* hg_mod_ctor()
{ return new HttpInspectModule; }

// this can be used for both modules
static void mod_dtor(Module* m)
{ delete m; }

static Inspector* hg_ctor(Module* m)
{
    HttpInspectModule* mod = (HttpInspectModule*)m;
    HTTPINSPECT_GLOBAL_CONF* gc = mod->get_data();
    HttpData* p = new HttpData(gc);
    return p;
}

static void hg_dtor(Inspector* p)
{ delete p; }

static const InspectApi hg_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        GLOBAL_KEYWORD,
        GLOBAL_HELP,
        hg_mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    (uint16_t)PktType::NONE,
    nullptr, // buffers
    "http",
    nullptr, // init,
    nullptr, // term,
    nullptr, // tinit
    nullptr, // tterm
    hg_ctor,
    hg_dtor,
    nullptr, // ssn
    nullptr  // reset
};

//-------------------------------------------------------------------------
// hs_* -> http_server (inspector)
//-------------------------------------------------------------------------

static Module* hs_mod_ctor()
{ return new HttpServerModule; }

static void hs_init()
{
    HttpFlowData::init();
    HI_SearchInit();
    hi_paf_init(0);  // FIXIT-L is cap needed?
    InitLookupTables();
    InitJSNormLookupTable();
}

static void hs_term()
{
    HI_SearchFree();
    hi_paf_term();
}

static Inspector* hs_ctor(Module* m)
{
    HttpServerModule* mod = (HttpServerModule*)m;
    return new HttpInspect(mod->get_data());
}

static void hs_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const char* buffers[] =
{
    "http_client_body",
    "http_cookie",
    "http_header",
    "http_method",
    "http_raw_cookie",
    "http_raw_header",
    "http_raw_uri",
    "http_stat_code",
    "http_stat_msg",
    "http_uri",
    nullptr
};

static const InspectApi hi_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SERVER_KEYWORD,
        SERVER_HELP,
        hs_mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    buffers,
    "http",
    hs_init,
    hs_term,
    nullptr, // tinit
    nullptr, // tterm
    hs_ctor,
    hs_dtor,
    nullptr, // ssn
    nullptr  // reset
};

// can't be built dynamically yet
//#ifdef BUILDING_SO
//SO_PUBLIC const BaseApi* snort_plugins[] =
//{
//    &hg_api.base,
//    &hi_api.base,
//    nullptr
//};
//#else
const BaseApi* sin_http_global = &hg_api.base;
const BaseApi* sin_http_inspect = &hi_api.base;
//#endif

