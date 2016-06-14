/*
*  $Id: mpse.c,v 1.2 2015/03/25 14:45:18 andrbake Exp $
*
*   mpse.c
*
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
*   Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
*   Copyright (C) 2002-2013 Sourcefire, Inc.
*   Marc A Norton <mnorton@sourcefire.com>
*
*   Updates:
*   3/06 - Added AC_BNFA search
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
*/
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "bitop.h"
#include "bnfa_search.h"
#include "acsmx.h"
#include "acsmx2.h"
#include "sfksearch.h"
#include "mpse.h"
#include "snort_debug.h"
#include "sf_types.h"
#include "util.h"

#ifdef DYNAMIC_PREPROC_CONTEXT
#include "sf_dynamic_preprocessor.h"
#endif //DYNAMIC_PREPROC_CONTEXT

#ifdef INTEL_SOFT_CPM
#include "intel-soft-cpm.h"
#endif
#include "profiler.h"
#ifndef DYNAMIC_PREPROC_CONTEXT
#include "snort.h"
#endif
#ifdef PERF_PROFILING
PreprocStats mpsePerfStats;
#endif

static uint64_t s_bcnt=0;

typedef struct _mpse_struct
{
    int method;
    void* obj;
    int verbose;
    uint64_t bcnt;
    char inc_global_counter;
} MPSE;

void* mpseNew(int method, int use_global_counter_flag,
    void (* userfree)(void* p),
    void (* optiontreefree)(void** p),
    void (* neg_list_free)(void** p))
{
    MPSE* p;

    p = (MPSE*)snort_calloc(sizeof(MPSE) );
    p->method = method;
    p->verbose = 0;
    p->obj = nullptr;
    p->bcnt = 0;
    p->inc_global_counter = (char)use_global_counter_flag;

    switch ( method )
    {
    case MPSE_AC_BNFA:
        p->obj=bnfaNew(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            ((bnfa_struct_t*)(p->obj))->bnfaMethod = 1;
        break;
    case MPSE_AC_BNFA_Q:
        p->obj=bnfaNew(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            ((bnfa_struct_t*)(p->obj))->bnfaMethod = 0;
        break;
    case MPSE_AC:
        p->obj = acsmNew(userfree, optiontreefree, neg_list_free);
        break;
    case MPSE_ACF:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_FULL);
        break;
    case MPSE_ACF_Q:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_FULLQ);
        break;
    case MPSE_ACS:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSE);
        break;
    case MPSE_ACB:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_BANDED);
        break;
    case MPSE_ACSB:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSEBANDS);
        break;
    case MPSE_LOWMEM:
        p->obj = KTrieNew(0,userfree, optiontreefree, neg_list_free);
        break;
    case MPSE_LOWMEM_Q:
        p->obj = KTrieNew(1,userfree, optiontreefree, neg_list_free);
        break;
    default:
        /* p is free'd below if no case */
        break;
    }

    if ( !p->obj )
    {
        snort_free(p);
        p = nullptr;
    }

    return (void*)p;
}

#ifndef DYNAMIC_PREPROC_CONTEXT
void* mpseNewWithSnortConfig(struct _SnortConfig* sc,
    int method, int use_global_counter_flag,
    void (* userfree)(void* p),
    void (* optiontreefree)(void** p),
    void (* neg_list_free)(void** p))
{
    MPSE* p;

    p = (MPSE*)snort_calloc(sizeof(MPSE) );
    p->method = method;
    p->verbose = 0;
    p->obj = nullptr;
    p->bcnt = 0;
    p->inc_global_counter = (char)use_global_counter_flag;

    switch ( method )
    {
    case MPSE_AC_BNFA:
        p->obj=bnfaNew(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            ((bnfa_struct_t*)(p->obj))->bnfaMethod = 1;
        break;
    case MPSE_AC_BNFA_Q:
        p->obj=bnfaNew(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            ((bnfa_struct_t*)(p->obj))->bnfaMethod = 0;
        break;
    case MPSE_AC:
        p->obj = acsmNew(userfree, optiontreefree, neg_list_free);
        break;
    case MPSE_ACF:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_FULL);
        break;
    case MPSE_ACF_Q:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_FULLQ);
        break;
    case MPSE_ACS:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSE);
        break;
    case MPSE_ACB:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_BANDED);
        break;
    case MPSE_ACSB:
        p->obj = acsmNew2(userfree, optiontreefree, neg_list_free);
        if (p->obj)
            acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSEBANDS);
        break;
    case MPSE_LOWMEM:
        p->obj = KTrieNew(0,userfree, optiontreefree, neg_list_free);
        break;
    case MPSE_LOWMEM_Q:
        p->obj = KTrieNew(1,userfree, optiontreefree, neg_list_free);
        break;
#ifdef INTEL_SOFT_CPM
    case MPSE_INTEL_CPM:
        p->obj=IntelPmNew(sc, userfree, optiontreefree, neg_list_free);
        break;
#endif
    default:
        /* p is free'd below if no case */
        break;
    }

    if ( !p->obj )
    {
        snort_free(p);
        p = nullptr;
    }

    return (void*)p;
}

#endif //DYNAMIC_PREPROC_CONTEXT

void mpseVerbose(void* pvoid)
{
    MPSE* p = (MPSE*)pvoid;
    p->verbose = 1;
}

void mpseSetOpt(void* pvoid, int flag)
{
    MPSE* p = (MPSE*)pvoid;

    if (p == nullptr)
        return;
    switch ( p->method )
    {
    case MPSE_AC_BNFA_Q:
    case MPSE_AC_BNFA:
        if (p->obj)
            bnfaSetOpt((bnfa_struct_t*)p->obj,flag);
        break;
    case MPSE_ACF:
    case MPSE_ACF_Q:
        if (p->obj)
            acsmCompressStates((ACSM_STRUCT2*)p->obj, flag);
        break;
    default:
        break;
    }
}

void mpseFree(void* pvoid)
{
    MPSE* p = (MPSE*)pvoid;

    if (p == nullptr)
        return;

    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        if (p->obj)
            bnfaFree((bnfa_struct_t*)p->obj);
        snort_free(p);
        return;

    case MPSE_AC:
        if (p->obj)
            acsmFree((ACSM_STRUCT*)p->obj);
        snort_free(p);
        return;

    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        if (p->obj)
            acsmFree2((ACSM_STRUCT2*)p->obj);
        snort_free(p);
        return;

    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        if (p->obj)
            KTrieDelete((KTRIE_STRUCT*)p->obj);
        snort_free(p);
        return;

#ifdef INTEL_SOFT_CPM
    case MPSE_INTEL_CPM:
        if (p->obj)
            IntelPmDelete((IntelPm*)p->obj);
        snort_free(p);
        break;
#endif

    default:
        snort_free(p);
        assert(false);
        return;
    }
}

int mpseAddPattern(void* pvoid, void* P, int m,
    unsigned noCase, unsigned offset, unsigned depth,
    unsigned negative, void* ID, int IID)
{
    MPSE* p = (MPSE*)pvoid;

    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        return bnfaAddPattern( (bnfa_struct_t*)p->obj, (unsigned char*)P, m,
            noCase, negative, ID);

    case MPSE_AC:
        return acsmAddPattern( (ACSM_STRUCT*)p->obj, (unsigned char*)P, m,
            noCase, offset, depth, negative, ID, IID);

    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        return acsmAddPattern2( (ACSM_STRUCT2*)p->obj, (unsigned char*)P, m,
            noCase, offset, depth, negative, ID, IID);

    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        return KTrieAddPattern( (KTRIE_STRUCT*)p->obj, (unsigned char*)P, m,
            noCase, negative, ID);
    default:
        return -1;
    }
}

#ifndef DYNAMIC_PREPROC_CONTEXT
int mpseAddPatternWithSnortConfig(SnortConfig* sc, void* pvoid, void* P, int m,
    unsigned noCase, unsigned offset, unsigned depth,
    unsigned negative, void* ID, int IID)
{
    MPSE* p = (MPSE*)pvoid;

    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        return bnfaAddPattern( (bnfa_struct_t*)p->obj, (unsigned char*)P, m,
            noCase, negative, ID);

    case MPSE_AC:
        return acsmAddPattern( (ACSM_STRUCT*)p->obj, (unsigned char*)P, m,
            noCase, offset, depth, negative, ID, IID);

    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        return acsmAddPattern2( (ACSM_STRUCT2*)p->obj, (unsigned char*)P, m,
            noCase, offset, depth, negative, ID, IID);

    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        return KTrieAddPattern( (KTRIE_STRUCT*)p->obj, (unsigned char*)P, m,
            noCase, negative, ID);
#ifdef INTEL_SOFT_CPM
    case MPSE_INTEL_CPM:
        return IntelPmAddPattern(sc, (IntelPm*)p->obj, (unsigned char*)P, m,
            noCase, negative, ID, IID);
#endif
    default:
        return -1;
    }
}

#endif // DYNAMIC_PREPROC_CONTEXT

void mpseLargeShifts(void* pvoid, int flag)
{
    MPSE* p = (MPSE*)pvoid;

    switch ( p->method )
    {
    default:
        return;
    }
}

int mpsePrepPatterns(void* pvoid,
    int ( * build_tree )(void* id, void** existing_tree),
    int ( * neg_list_func )(void* id, void** list) )
{
    int retv;
    MPSE* p = (MPSE*)pvoid;

    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        retv = bnfaCompile( (bnfa_struct_t*)p->obj, build_tree, neg_list_func);
        break;

    case MPSE_AC:
        retv = acsmCompile( (ACSM_STRUCT*)p->obj, build_tree, neg_list_func);
        break;

    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        retv = acsmCompile2( (ACSM_STRUCT2*)p->obj, build_tree, neg_list_func);
        break;

    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        return KTrieCompile( (KTRIE_STRUCT*)p->obj, build_tree, neg_list_func);

    default:
        retv = 1;
        break;
    }

    return retv;
}

#ifndef DYNAMIC_PREPROC_CONTEXT
int mpsePrepPatternsWithSnortConf(struct _SnortConfig* sc, void* pvoid,
    int ( * build_tree )(struct _SnortConfig*, void* id, void** existing_tree),
    int ( * neg_list_func )(void* id, void** list) )
{
    int retv;
    MPSE* p = (MPSE*)pvoid;

    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        retv = bnfaCompileWithSnortConf(sc, (bnfa_struct_t*)p->obj, build_tree, neg_list_func);
        break;

    case MPSE_AC:
        retv = acsmCompileWithSnortConf(sc, (ACSM_STRUCT*)p->obj, build_tree, neg_list_func);
        break;

    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        retv = acsmCompile2WithSnortConf(sc, (ACSM_STRUCT2*)p->obj, build_tree, neg_list_func);
        break;

    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        return KTrieCompileWithSnortConf(sc, (KTRIE_STRUCT*)p->obj, build_tree, neg_list_func);

#ifdef INTEL_SOFT_CPM
    case MPSE_INTEL_CPM:
        return IntelPmFinishGroup(sc, (IntelPm*)p->obj, build_tree, neg_list_func);
#endif

    default:
        retv = 1;
        break;
    }

    return retv;
}

#endif //DYNAMIC_PREPROC_CONTEXT

void mpseSetRuleMask(void* pvoid, BITOP* rm)
{
    MPSE* p = (MPSE*)pvoid;

    switch ( p->method )
    {
    default:
        return;
    }
}

int mpsePrintInfo(void* pvoid)
{
    MPSE* p = (MPSE*)pvoid;

    fflush(stderr);
    fflush(stdout);
    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        bnfaPrintInfo( (bnfa_struct_t*)p->obj);
        break;
    case MPSE_AC:
        return acsmPrintDetailInfo( (ACSM_STRUCT*)p->obj);
    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        return acsmPrintDetailInfo2( (ACSM_STRUCT2*)p->obj);

    default:
        return 1;
    }
    fflush(stderr);
    fflush(stdout);

    return 0;
}

int mpsePrintSummary(int method)
{
    switch (method)
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        bnfaPrintSummary();
        break;
    case MPSE_AC:
        acsmPrintSummaryInfo();
        break;
    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        acsmPrintSummaryInfo2();
        break;
    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        if ( KTrieMemUsed() )
        {
            double x;
            x = (double)KTrieMemUsed();
            LogMessage("[ LowMem Search-Method Memory Used : %g %s ]\n",
                (x > 1.e+6) ?  x/1.e+6 : x/1.e+3,
                (x > 1.e+6) ? "MBytes" : "KBytes");
        }
        break;
    default:
        break;
    }

    return 0;
}

#ifndef DYNAMIC_PREPROC_CONTEXT
int mpsePrintSummaryWithSnortConfig(SnortConfig* sc, int method)
{
    switch (method)
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        bnfaPrintSummary();
        break;
    case MPSE_AC:
        acsmPrintSummaryInfo();
        break;
    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        acsmPrintSummaryInfo2();
        break;
    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        if ( KTrieMemUsed() )
        {
            double x;
            x = (double)KTrieMemUsed();
            LogMessage("[ LowMem Search-Method Memory Used : %g %s ]\n",
                (x > 1.e+6) ?  x/1.e+6 : x/1.e+3,
                (x > 1.e+6) ? "MBytes" : "KBytes");
        }
        break;
    default:
        break;
    }

#ifdef INTEL_SOFT_CPM
    IntelPmPrintSummary(sc);
#endif

    return 0;
}

#endif //DYNAMIC_PREPROC_CONTEXT

void mpseInitSummary(void)
{
    acsm_init_summary();
    bnfaInitSummary();
    KTrieInitMemUsed();
}

int mpseSearch(void* pvoid, const unsigned char* T, int n,
    int ( * action )(void* id, void* tree, int index, void* data, void* neg_list),
    void* data, int* current_state)
{
    MPSE* p = (MPSE*)pvoid;
    int ret;
    PROFILE_VARS;

    PREPROC_PROFILE_START(mpsePerfStats);

    p->bcnt += n;

    if (p->inc_global_counter)
        s_bcnt += n;

    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        /* return is actually the state */
        ret = bnfaSearch((bnfa_struct_t*)p->obj, (unsigned char*)T, n,
            action, data, 0 /* start-state */, current_state);
        PREPROC_PROFILE_END(mpsePerfStats);
        return ret;

    case MPSE_AC:
        ret = acsmSearch( (ACSM_STRUCT*)p->obj, (unsigned char*)T, n, action, data, current_state);
        PREPROC_PROFILE_END(mpsePerfStats);
        return ret;

    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        ret = acsmSearch2( (ACSM_STRUCT2*)p->obj, (unsigned char*)T, n, action, data,
            current_state);
        PREPROC_PROFILE_END(mpsePerfStats);
        return ret;

    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        ret = KTrieSearch( (KTRIE_STRUCT*)p->obj, (unsigned char*)T, n, action, data);
        *current_state = 0;
        PREPROC_PROFILE_END(mpsePerfStats);
        return ret;

#ifdef INTEL_SOFT_CPM
    case MPSE_INTEL_CPM:
        ret = IntelPmSearch((IntelPm*)p->obj, (unsigned char*)T, n, action, data);
        *current_state = 0;
        PREPROC_PROFILE_END(mpsePerfStats);
        return ret;
#endif

    default:
        PREPROC_PROFILE_END(mpsePerfStats);
        return 1;
    }
}

int mpseSearchAll(void* pvoid, const unsigned char* T, int n,
    int ( * action )(void* id, void* tree, int index, void* data, void* neg_list),
    void* data, int* current_state)
{
    MPSE* p = (MPSE*)pvoid;
    int ret;
    PROFILE_VARS;

    PREPROC_PROFILE_START(mpsePerfStats);

    p->bcnt += n;

    if (p->inc_global_counter)
        s_bcnt += n;

    switch ( p->method )
    {
    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        ret = acsmSearchAll2( (ACSM_STRUCT2*)p->obj, (unsigned char*)T, n, action, data,
            current_state);
        PREPROC_PROFILE_END(mpsePerfStats);
        return ret;

    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
    case MPSE_AC:
    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
#ifdef INTEL_SOFT_CPM
    case MPSE_INTEL_CPM:
#endif
    default:
        //search all not implemented.
        PREPROC_PROFILE_END(mpsePerfStats);
        return 1;
    }
}

int mpseGetPatternCount(void* pvoid)
{
    MPSE* p = (MPSE*)pvoid;

    if (p == nullptr)
        return 0;

    switch ( p->method )
    {
    case MPSE_AC_BNFA:
    case MPSE_AC_BNFA_Q:
        return bnfaPatternCount((bnfa_struct_t*)p->obj);
    case MPSE_AC:
        return acsmPatternCount((ACSM_STRUCT*)p->obj);
    case MPSE_ACF:
    case MPSE_ACF_Q:
    case MPSE_ACS:
    case MPSE_ACB:
    case MPSE_ACSB:
        return acsmPatternCount2((ACSM_STRUCT2*)p->obj);
    case MPSE_LOWMEM:
    case MPSE_LOWMEM_Q:
        return KTriePatternCount((KTRIE_STRUCT*)p->obj);
#ifdef INTEL_SOFT_CPM
    case MPSE_INTEL_CPM:
        return IntelGetPatternCount((IntelPm*)p->obj);
#endif
    }
    return 0;
}

uint64_t mpseGetPatByteCount(void)
{
    return s_bcnt;
}

void mpseResetByteCount(void)
{
    s_bcnt = 0;
}

void mpse_print_qinfo(void)
{
    sfksearch_print_qinfo();
    bnfa_print_qinfo();
    acsmx2_print_qinfo();
}

