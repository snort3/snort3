/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

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

/*
FIXIT if HI is built dynamically, Snort get these undefineds:
Undefined symbols for architecture x86_64:
  "IsGzipData(Flow*)", referenced from:
      LogIPPkt(_TextLog*, int, Packet*) in liblog.a(log_text.o)
  "IsJSNormData(Flow*)", referenced from:
      LogIPPkt(_TextLog*, int, Packet*) in liblog.a(log_text.o)
  "GetHttpUriData(Flow*, unsigned char**, unsigned int*, unsigned int*)", referenced from:
      add_file_to_block(Packet*, _File_Verdict, unsigned int, unsigned char*) in libfile_api.a(file_service.o)
      check_http_partial_content(Packet*)      in libfile_api.a(file_service.o)
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "protocols/packet.h"
#include "snort_debug.h"
#include "util.h"
#include "parser.h"

#include "hi_client.h"
#include "hi_ui_config.h"
#include "hi_module.h"
#include "hi_norm.h"
#include "hi_main.h"
#include "hi_util_kmap.h"
#include "hi_util_xmalloc.h"
#include "hi_cmd_lookup.h"
#include "hi_paf.h"

#include "snort.h"
#include "profiler.h"
#include "mstring.h"
#include "detection_util.h"

#include "stream/stream_api.h"
#include "target_based/sftarget_protocol_reference.h"
#include "file_api/file_api.h"
#include "sf_email_attach_decode.h"
#include "framework/inspector.h"
#include "framework/share.h"

#define ERRSTRLEN 1000

/* Store the protocol id received from the stream reassembler */
int16_t hi_app_protocol_id = SFTARGET_UNKNOWN_PROTOCOL;

int hex_lookup[256];
int valid_lookup[256];

#ifdef PERF_PROFILING
// hiDetectPerfStats is not registered; it is used
// only to exclude detection from hiPerfStats
THREAD_LOCAL PreprocStats hiPerfStats;
THREAD_LOCAL PreprocStats hiDetectPerfStats;

static PreprocStats* hi_get_profile(const char* key)
{
    if ( !strcmp(key, SERVER_KEYWORD) )
        return &hiPerfStats;

    return nullptr;
}
#endif

static HIStats ghi_stats;

static const char* peg_names[] =
{
    "packets",
    "gets",
    "posts",

    "request headers",
    "response headers",
    "request cookies",
    "response cookies",
    "post params",

    "unicode",
    "double unicode",
    "non-ascii",
    "paths with ../",
    "paths with //",
    "paths with ./",

    "gzip packets",
    "compressed bytes",
    "decompressed bytes",
};

THREAD_LOCAL int hiDetectCalled = 0;

/*
** Prototypes
*/
#if 0
// FIXIT see below
static int HttpEncodeInit(SnortConfig*, char *, char *, void **);
static int HttpEncodeEval(Packet*, const uint8_t **, void *);
static void HttpEncodeCleanup(void *);
#endif
static void HttpInspectRegisterRuleOptions(SnortConfig*);
static inline void InitLookupTables(void);
static void CheckGzipConfig(HTTPINSPECT_GLOBAL_CONF*);
static void CheckMemcap(HTTPINSPECT_GLOBAL_CONF*);

static void CheckGzipConfig(HTTPINSPECT_GLOBAL_CONF *pPolicyConfig)
{
    if (!pPolicyConfig->max_gzip_mem)
        pPolicyConfig->max_gzip_mem = DEFAULT_MAX_GZIP_MEM;

    if (!pPolicyConfig->compr_depth)
        pPolicyConfig->compr_depth = DEFAULT_COMP_DEPTH;

    if (!pPolicyConfig->decompr_depth)
        pPolicyConfig->decompr_depth = DEFAULT_DECOMP_DEPTH;

    pPolicyConfig->max_gzip_sessions =
        pPolicyConfig->max_gzip_mem / sizeof(DECOMPRESS_STATE);
}

static void CheckMemcap(HTTPINSPECT_GLOBAL_CONF *pPolicyConfig)
{
    if (!pPolicyConfig->memcap)
        pPolicyConfig->memcap = DEFAULT_HTTP_MEMCAP;
}

static void HttpInspectRegisterRuleOptions(SnortConfig*)
{
#if 0
    // FIXIT implement preproc rule option as any other
    RegisterPreprocessorRuleOption(
        sc, "http_encode", &HttpEncodeInit, &HttpEncodeEval,
        &HttpEncodeCleanup , NULL, NULL, NULL, NULL);
#endif
}

static void updateConfigFromFileProcessing (HTTPINSPECT_CONF* ServerConf)
{
    /*Either one is unlimited*/
    int64_t fileDepth = file_api->get_max_file_depth();

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
    HttpInspectRegisterXtraDataFuncs();  // FIXIT must be done once

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
    for(iCtr = 48; iCtr < 58; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }

    /*
    * Set the upper case values.
    */
    iNum = 10;
    for(iCtr = 65; iCtr < 71; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }

    /*
     *  Set the lower case values.
     */
    iNum = 10;
    for(iCtr = 97; iCtr < 103; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
   }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

typedef PlugDataType<HTTPINSPECT_GLOBAL_CONF> HttpData;

class HttpInspect : public Inspector {
public:
    HttpInspect(HTTPINSPECT_CONF*);
    ~HttpInspect();

    bool configure(SnortConfig*);
    void show(SnortConfig*);

    StreamSplitter* get_splitter(bool c2s)
    { return new HttpSplitter(c2s); };

    void eval(Packet*);

    void pinit();
    void pterm();

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
        Share::release(global);
}

bool HttpInspect::configure (SnortConfig* sc)
{
    global = (HttpData*)Share::acquire(GLOBAL_KEYWORD);
    config->global = global->data;

    // FIXIT this is one time stuff (done for 1st instance)
    // need api support for one time stuff or what?
    HttpInspectRegisterRuleOptions(sc);
    HttpInspectInitializeGlobalConfig(config->global);

    // FIXIT must load default unicode map from const char*
    CheckGzipConfig(config->global);
    CheckMemcap(config->global);

    return !HttpInspectVerifyPolicy(sc, config);
}

void HttpInspect::pinit()
{
    memset(&hi_stats, 0, sizeof(HIStats));

    config->global->decode_conf.file_depth = file_api->get_max_file_depth();

    if (config->global->decode_conf.file_depth > -1)
        config->global->mime_conf.log_filename = 1;

    if ( (config->post_extract_size > -1) &&
        file_api->is_decoding_enabled(&config->global->decode_conf) )
    {
        updateMaxDepth(config->global->decode_conf.file_depth, &config->global->decode_conf.max_depth);

    }
}

void HttpInspect::pterm()
{
}

void HttpInspect::show(SnortConfig*)
{
    PrintGlobalConf(config->global);

    LogMessage("    DEFAULT SERVER CONFIG:\n");
    PrintServerConf(config);
}

void HttpInspect::eval (Packet* p)
{
    PROFILE_VARS;

    // preconditions - what we registered for
    assert(IsTCP(p) && p->dsize && p->data);

    PREPROC_PROFILE_START(hiPerfStats);

    HttpInspectMain(config, p);

    ClearHttpBuffers();

    /* XXX:
     * NOTE: this includes the HTTPInspect directly
     * calling the detection engine -
     * to get the true HTTPInspect only stats, have another
     * var inside HttpInspectMain that tracks the time
     * spent in Detect().
     * Subtract the ticks from this if iCallDetect == 0
     */
    PREPROC_PROFILE_END(hiPerfStats);
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

static PlugData* hg_ctor(Module* m)
{
    HttpInspectModule* mod = (HttpInspectModule*)m;
    HTTPINSPECT_GLOBAL_CONF* gc = mod->get_data();
    HttpData* p = new HttpData(gc);
    return p;
}

static void hg_dtor(PlugData* p)
{ delete p; }

static const DataApi hg_api =
{
    {
        PT_DATA,
        GLOBAL_KEYWORD,
        MODAPI_PLUGIN_V0,
        0,
        hg_mod_ctor,
        mod_dtor
    },
    hg_ctor,
    hg_dtor
};

//-------------------------------------------------------------------------
// hs_* -> http_server (inspector)
//-------------------------------------------------------------------------

static Module* hs_mod_ctor()
{ return new HttpServerModule; }

static void hs_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        SERVER_KEYWORD, &hiPerfStats, 0, &totalPerfStats, hi_get_profile);
#endif

    /* Find and cache protocol ID for packet comparison */
    hi_app_protocol_id = AddProtocolReference("http");

    hi_paf_init(0);  // FIXTHIS is cap needed?
    HttpFlowData::init();
    HI_SearchInit();
    InitLookupTables();
    InitJSNormLookupTable();
}

static void hs_term()
{
    hi_paf_term();
    HI_SearchFree();
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

static void hs_sum()
{
    sum_stats((PegCount*)&ghi_stats, (PegCount*)&hi_stats, array_size(peg_names));
}

static void hs_stats()
{
    show_stats((PegCount*)&ghi_stats, peg_names, array_size(peg_names),
        SERVER_KEYWORD);
}

static void hs_reset()
{
    memset(&ghi_stats, 0, sizeof(ghi_stats));
}

//-------------------------------------------------------------------------

static const InspectApi hs_api =
{
    {
        PT_INSPECTOR,
        SERVER_KEYWORD,
        INSAPI_PLUGIN_V0,
        0,
        hs_mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__TCP,
    "http",
    hs_init,
    hs_term,
    hs_ctor,
    hs_dtor,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // ssn
    hs_sum,
    hs_stats,
    hs_reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &hg_api.base,
    &hs_api.base,
    nullptr
};
#else
const BaseApi* sin_http_global = &hg_api.base;
const BaseApi* sin_http_server = &hs_api.base;
#endif

