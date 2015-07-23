//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// @file    sfdaq.c
// @author  Russ Combs <rcombs@sourcefire.com>

#include "sfdaq.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <mutex>
using namespace std;

extern "C" {
#include <daq.h>
#include <sfbpf_dlt.h>
}

#include "main/snort_config.h"
#include "utils/util.h"
#include "utils/strvec.h"
#include "parser/parser.h"

#define PKT_SNAPLEN  1514

#ifdef DEFAULT_DAQ
#define XSTR(s) STR(s)
#define STR(s) #s
#define DAQ_DEFAULT XSTR(DEFAULT_DAQ)
#else
#define DAQ_DEFAULT "pcap"
#endif

#ifndef DAQ_CAPA_INJECT_RAW
#define DAQ_CAPA_INJECT_RAW 0x200
#endif

// common for all daq threads / instances
static const DAQ_Module_t* daq_mod = NULL;
static DAQ_Mode daq_mode = DAQ_MODE_PASSIVE;
static uint32_t snap = PKT_SNAPLEN;
static int loaded = 0;

// specific for each thread / instance
static THREAD_LOCAL char* interface_spec = NULL;
static THREAD_LOCAL void* daq_hand = NULL;
static THREAD_LOCAL int daq_dlt = -1;
static THREAD_LOCAL int s_error = DAQ_SUCCESS;
static THREAD_LOCAL DAQ_Stats_t daq_stats, tot_stats;

static void DAQ_Accumulate(void);

//--------------------------------------------------------------------

void DAQ_Load(const SnortConfig* sc)
{
    const char** dirs = StringVector_GetVector(sc->daq_dirs);

    int err = daq_load_modules(dirs);

    if ( err )
        FatalError("Can't load DAQ modules = %d\n", err);

    loaded = 1;
}

void DAQ_Unload()
{
    daq_unload_modules();
    loaded = 0;
}

//--------------------------------------------------------------------

int DAQ_PrintTypes(FILE* f)
{
    DAQ_Module_Info_t* list = NULL;
    int i, nMods = daq_get_module_list(&list);

    if ( nMods )
        fprintf(f, "Available DAQ modules:\n");
    else
        fprintf(f, "No available DAQ modules "
            "(try adding directories with --daq-dir).\n");

    for ( i = 0; i < nMods; i++ )
    {
        fprintf(f, "%s(v%u):", list[i].name, list[i].version);

        if ( list[i].type & DAQ_TYPE_FILE_CAPABLE )
            fprintf(f, " %s", "readback");

        if ( list[i].type & DAQ_TYPE_INTF_CAPABLE )
            fprintf(f, " %s", "live");

        if ( list[i].type & DAQ_TYPE_INLINE_CAPABLE )
            fprintf(f, " %s", "inline");

        if ( list[i].type & DAQ_TYPE_MULTI_INSTANCE )
            fprintf(f, " %s", "multi");

        if ( !(list[i].type & DAQ_TYPE_NO_UNPRIV) )
            fprintf(f, " %s", "unpriv");

        fprintf(f, "\n");
    }
    daq_free_module_list(list, nMods);
    return 0;
}

DAQ_Mode DAQ_GetInterfaceMode(const DAQ_PktHdr_t* h)
{
#ifdef DAQ_PKT_FLAG_NOT_FORWARDING
    // interface is not inline, so return passive
    if (h->flags & DAQ_PKT_FLAG_NOT_FORWARDING)
        return DAQ_MODE_PASSIVE;
#endif
    // interface is inline
    if ( SnortConfig::adaptor_inline_mode() )
    {
        return DAQ_MODE_INLINE;
    }

    // interface is passive or readback
    return DAQ_MODE_PASSIVE;
}

DAQ_Mode DAQ_GetMode(const SnortConfig* sc)
{
    if ( sc->daq_mode.size() )
    {
        int i;

        for ( i = 0; i < MAX_DAQ_MODE; i++ )
        {
            if ( !strcasecmp(daq_mode_string((DAQ_Mode)i), sc->daq_mode.c_str()) )
            {
                if ( SnortConfig::adaptor_inline_mode() && (i != DAQ_MODE_INLINE) )
                    FatalError("DAQ '%s' mode incompatible with -Q\n", sc->daq_mode.c_str());
                return (DAQ_Mode)i;
            }
        }
        FatalError("Bad DAQ mode '%s'\n", sc->daq_mode.c_str());
    }
    if ( SnortConfig::adaptor_inline_mode() )
        return DAQ_MODE_INLINE;

    if ( SnortConfig::read_mode() )
        return DAQ_MODE_READ_FILE;

    return DAQ_MODE_PASSIVE;
}

//--------------------------------------------------------------------

static int DAQ_ValidateModule(DAQ_Mode mode)
{
    uint32_t have = daq_get_type(daq_mod);
    uint32_t need = 0;

    if ( mode == DAQ_MODE_READ_FILE )
        need |= DAQ_TYPE_FILE_CAPABLE;

    else if ( mode == DAQ_MODE_PASSIVE )
        need |= DAQ_TYPE_INTF_CAPABLE;

    else
        need |= DAQ_TYPE_INLINE_CAPABLE;

    return ( (have & need) != 0 );
}

static int DAQ_ValidateInstance()
{
    uint32_t caps = daq_get_capabilities(daq_mod, daq_hand);

    if ( !SnortConfig::adaptor_inline_mode() )
        return 1;

    if ( !(caps & DAQ_CAPA_BLOCK) )
        ParseWarning(WARN_DAQ, "inline mode configured but DAQ can't block packets.\n");

#if 0
    // this is checked in normalize.c and sp_respond.c
    // and warned/disabled only if it was configured
    if ( !(caps & DAQ_CAPA_REPLACE) )
    {
        ParseWarning(WARN_DAQ, "normalizations/replacements disabled "
            " because DAQ can't replace packets.\n");
    }

    // this is checked in spp_stream.c and active.c
    // and warned/disabled only if it was configured
    if ( !(caps & DAQ_CAPA_INJECT) )
        ParseWarning(WARN_DAQ, "inline mode configured but DAQ can't "
            "inject packets.\n");
#endif

    return 1;
}

//--------------------------------------------------------------------

void DAQ_Init(const SnortConfig* sc)
{
    if ( !loaded )
        DAQ_Load(sc);

    const char* type = DAQ_DEFAULT;

    if ( sc->daq_type.size() )
        type = sc->daq_type.c_str();

    daq_mod = daq_find_module(type);

    if ( !daq_mod )
        FatalError("Can't find %s DAQ\n", type);

    snap = ( sc->pkt_snaplen > 0 ) ? sc->pkt_snaplen : PKT_SNAPLEN;
    daq_mode = DAQ_GetMode(sc);

    if ( !DAQ_ValidateModule(daq_mode) )
        FatalError("%s DAQ does not support %s.\n",
            type, daq_mode_string(daq_mode));

    LogMessage("%s DAQ configured to %s.\n",
        type, daq_mode_string(daq_mode));
}

void DAQ_Term()
{
//#ifndef VALGRIND_TESTING
    if ( loaded )
        DAQ_Unload();
    daq_mod = NULL;
//#endif
}

void DAQ_Abort()
{
    if ( DAQ_WasStarted() )
        DAQ_Stop();

    DAQ_Delete();
    //DAQ_Term();  FIXIT-L this must be called from main thread on abort
}

//--------------------------------------------------------------------

const char* DAQ_GetInterfaceSpec(void)
{
    return interface_spec ? interface_spec : "";
}

const char* DAQ_GetType(void)
{
    return daq_mod ? daq_get_name(daq_mod) : "error";
}

// Snort has its own snap applied to packets it acquires via the DAQ.  This
// should not be confused with the snap that was used to capture a pcap which
// may be different.
uint32_t DAQ_GetSnapLen(void)
{
    return snap;
}

// That distinction does not hold with datalink types.  Snort must use whatever
// datalink type the DAQ coughs up as its base protocol decoder.  For pcaps,
// the datalink type in the file must be used - which may not be known until
// start.  The value is cached here since it used for packet operations like
// logging and is needed at shutdown.  this avoids sequencing issues.
int DAQ_GetBaseProtocol(void)
{
    return daq_dlt;
}

int DAQ_Unprivileged(void)
{
    return !( daq_get_type(daq_mod) & DAQ_TYPE_NO_UNPRIV );
}

int DAQ_UnprivilegedStart(void)
{
    return ( daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_UNPRIV_START );
}

int DAQ_CanReplace(void)
{
    return ( daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_REPLACE );
}

int DAQ_CanInject(void)
{
    return ( daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_INJECT );
}

int DAQ_CanWhitelist(void)
{
#ifdef DAQ_CAPA_WHITELIST
    return ( daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_WHITELIST );
#else
    return 0;
#endif
}

int DAQ_RawInjection(void)
{
    return ( daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_INJECT_RAW );
}

int DAQ_SetFilter(const char* bpf)
{
    int err = 0;
    static mutex bpf_gate;

    // doesn't look like the bpf flex scanner is reentrant
    bpf_gate.lock();

    if ( bpf and *bpf )
        err = daq_set_filter(daq_mod, daq_hand, bpf);

    bpf_gate.unlock();

    if ( err )
        FatalError("Can't set DAQ BPF filter to '%s' (%s)\n",
            bpf, daq_get_error(daq_mod, daq_hand));

    return err;
}

//--------------------------------------------------------------------

static void DAQ_LoadVars(DAQ_Config_t* cfg, const SnortConfig* sc)
{
    unsigned i = 0;

    do
    {
        char* key = StringVector_Get(sc->daq_vars, i++);
        char* val = NULL;

        if ( !key )
            break;

        while ( isspace(*key) )
            ++key;

        val = strchr(key, '=');

        if ( val )
            *val++ = '\0';

        daq_config_set_value(cfg, key, val);

        if ( val )
            *--val = '=';
    }
    while ( 1 );
}

static int DAQ_Config(DAQ_Config_t* cfg)
{
    int err;
    char buf[256] = "";
    const char* type = daq_get_name(daq_mod);

    // ideally this would be configurable ...
    if ( !strcasecmp(type, "dump") )
        cfg->extra = (char*)daq_find_module("pcap");

    err = daq_initialize(daq_mod, cfg, &daq_hand, buf, sizeof(buf));

    if ( err )
        ErrorMessage("Can't initialize DAQ %s (%d) - %s\n", type, err, buf);

    return err;
}

//--------------------------------------------------------------------

int DAQ_New(const SnortConfig* sc, const char* intf)
{
    DAQ_Config_t cfg;

    if ( !daq_mod )
        FatalError("DAQ_Init not called\n");

    if ( intf )
        interface_spec = SnortStrdup(intf);
    intf = DAQ_GetInterfaceSpec();

    memset(&cfg, 0, sizeof(cfg));
    cfg.name = (char*)intf;
    cfg.snaplen = snap;
    cfg.timeout = PKT_TIMEOUT;
    cfg.mode = daq_mode;
    cfg.extra = NULL;
    cfg.flags = 0;

    DAQ_LoadVars(&cfg, sc);

    if ( !SnortConfig::read_mode() )
    {
        if ( !(sc->run_flags & RUN_FLAG__NO_PROMISCUOUS) )
            cfg.flags |= DAQ_CFG_PROMISC;
    }

    if ( DAQ_Config(&cfg) )
        return -1;

    if ( !DAQ_ValidateInstance() )
        FatalError("DAQ configuration incompatible with intended operation.\n");

    if ( DAQ_UnprivilegedStart() )
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);

    DAQ_SetFilter(sc->bpf_filter.c_str());
    daq_config_clear_values(&cfg);

    memset(&daq_stats, 0, sizeof(daq_stats));
    memset(&tot_stats, 0, sizeof(tot_stats));

    return 0;
}

int DAQ_Delete(void)
{
    if ( daq_hand )
    {
        DAQ_Accumulate();
        daq_shutdown(daq_mod, daq_hand);
        daq_hand = NULL;
    }
    if ( interface_spec )
    {
        free(interface_spec);
        interface_spec = NULL;
    }
    return 0;
}

//--------------------------------------------------------------------

int DAQ_Start()
{
    int err = daq_start(daq_mod, daq_hand);

    if ( err )
        ErrorMessage("Can't start DAQ (%d) - %s\n",
            err, daq_get_error(daq_mod, daq_hand));

    else if ( !DAQ_UnprivilegedStart() )
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);

    return err;
}

int DAQ_WasStarted(void)
{
    DAQ_State s;

    if ( !daq_mod || !daq_hand )
        return 0;

    s = daq_check_status(daq_mod, daq_hand);

    return ( DAQ_STATE_STARTED == s );
}

int DAQ_Stop()
{
    int err = daq_stop(daq_mod, daq_hand);

    if ( err )
        LogMessage("Can't stop DAQ (%d) - %s\n",
            err, daq_get_error(daq_mod, daq_hand));

    return err;
}

//--------------------------------------------------------------------

#ifdef HAVE_DAQ_ACQUIRE_WITH_META
static THREAD_LOCAL_TBD DAQ_Meta_Func_t daq_meta_callback = NULL;
void DAQ_Set_MetaCallback(DAQ_Meta_Func_t meta_callback)
{
    daq_meta_callback = meta_callback;
}

#endif

int DAQ_Acquire(int max, DAQ_Analysis_Func_t callback, uint8_t* user)
{
#if HAVE_DAQ_ACQUIRE_WITH_META
    int err = daq_acquire_with_meta(daq_mod, daq_hand, max, callback, daq_meta_callback, user);
#else
    int err = daq_acquire(daq_mod, daq_hand, max, callback, user);
#endif

    if ( err && err != DAQ_READFILE_EOF )
        LogMessage("Can't acquire (%d) - %s\n",
            err, daq_get_error(daq_mod, daq_hand));

    if ( s_error != DAQ_SUCCESS )
    {
        err = s_error;
        s_error = DAQ_SUCCESS;
    }
    return err;
}

int DAQ_Inject(const DAQ_PktHdr_t* h, int rev, const uint8_t* buf, uint32_t len)
{
    int err = daq_inject(daq_mod, daq_hand, (DAQ_PktHdr_t*)h, buf, len, rev);
#ifdef DEBUG
    if ( err )
        LogMessage("Can't inject (%d) - %s\n",
            err, daq_get_error(daq_mod, daq_hand));
#endif
    return err;
}

//--------------------------------------------------------------------

void* DAQ_GetHandle()
{ return daq_hand; }

int DAQ_BreakLoop(int error, void* hand)
{
    if ( !hand )
        hand = daq_hand;
    s_error = error;
    return ( daq_breakloop(daq_mod, hand) == DAQ_SUCCESS );
}

//--------------------------------------------------------------------

static void DAQ_Accumulate(void)
{
    int i;
    const DAQ_Stats_t* ps = DAQ_GetStats();

    tot_stats.hw_packets_received += ps->hw_packets_received;
    tot_stats.hw_packets_dropped += ps->hw_packets_dropped;
    tot_stats.packets_received += ps->packets_received;
    tot_stats.packets_filtered += ps->packets_filtered;
    tot_stats.packets_injected += ps->packets_injected;

    for ( i = 0; i < MAX_DAQ_VERDICT; i++ )
        tot_stats.verdicts[i] += ps->verdicts[i];
}

// returns statically allocated stats - don't free
const DAQ_Stats_t* DAQ_GetStats(void)
{
    int err = 0;

    if ( !daq_hand )
        return &tot_stats;

    err = daq_get_stats(daq_mod, daq_hand, &daq_stats);

    if ( err )
        LogMessage("Can't get DAQ stats (%d) - %s\n",
            err, daq_get_error(daq_mod, daq_hand));

    if ( !daq_stats.hw_packets_received )
        // some DAQs don't provide hw numbers
        // so we default hw rx to the sw equivalent
        // (this means outstanding packets = 0)
        daq_stats.hw_packets_received =
            daq_stats.packets_received + daq_stats.packets_filtered;

    return &daq_stats;
}

//--------------------------------------------------------------------

int DAQ_ModifyFlow(const void* h, uint32_t id)
{
#ifdef HAVE_DAQ_ACQUIRE_WITH_META
    const DAQ_PktHdr_t* hdr = (DAQ_PktHdr_t*)h;
    DAQ_ModFlow_t mod;

    mod.opaque = id;
    return daq_modify_flow(daq_mod, daq_hand, hdr, &mod);
#else
    UNUSED(h);
    UNUSED(id);
    return -1;
#endif
}

