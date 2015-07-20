//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

#include "intel_soft_cpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pm/cpa_pm_compile.h"
#include "utils/util.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"

/* MACROS *********************************************************************/
#define GROUP_ARRAY_ALLOC_SIZE 50
#define PATTERN_ARRAY_ALLOC_SIZE 10
#define MAX_INQ 32
#define DIM(x) (sizeof(x)/sizeof(x[0]))

/* DATA TYPES *****************************************************************/
typedef struct _IntelPmMatchQueue
{
    unsigned int inq;
    unsigned int inq_flush;
    void* q[MAX_INQ];
} IntelPmMatchQueue;

typedef struct _IntelPmMatchState
{
    void* user_data;
    void* rule_option_tree;
    void* neg_list;

    void (* user_free)(void*);
    void (* option_tree_free)(void**);
    void (* neg_list_free)(void**);
} IntelPmMatchState;

typedef struct _IntelPmHandles
{
    CpaPmPdbPatternSetHandle psh;  /* pattern set handle */
    CpaPmPdbHandle pdbh;  /* pattern database handle */
    Cpa16U pgids;  /* pattern group ids */
    Cpa32U pids;  /* pattern ids */
    Cpa32U pcs;  /* pattern characters */
    IntelPm** ipms;  /* pattern matchers */
    int ipms_len;
    IntelPmMatchState* pm_mtchs;
    int pm_mtchs_len;
    int refs;
} IntelPmHandles;

/* GLOBALS ********************************************************************/
static CpaInstanceHandle ipm_instance = NULL;  /* instance handle */

/* XXX Temporary stat for Intel */
//static uint64_t intel_pm_search_buf_sizes[65536];
//static uint64_t intel_pm_matches = 0;

/* PROTOTYPES *****************************************************************/
static inline const char* GetCpaStatusStr(CpaStatus);
static void IntelPmSearchCallback(const CpaInstanceHandle, CpaPmMatchCtx*);
static inline void IntelPmInitQueue(IntelPmMatchQueue*);
static inline int IntelPmAddQueue(IntelPmMatchQueue*, void*);
static inline unsigned int IntelPmProcessQueue(IntelPmMatchQueue*, MatchFunc, void*);
static void IntelPmRelease(IntelPmHandles*);

/* FUNCTIONS ******************************************************************/
static inline const char* GetCpaStatusStr(CpaStatus status)
{
    switch (status)
    {
    case CPA_STATUS_SUCCESS:
        return CPA_STATUS_STR_SUCCESS;
    case CPA_STATUS_FAIL:
        return CPA_STATUS_STR_FAIL;
    case CPA_STATUS_RETRY:
        return CPA_STATUS_STR_RETRY;
    case CPA_STATUS_RESOURCE:
        return CPA_STATUS_STR_RESOURCE;
    case CPA_STATUS_INVALID_PARAM:
        return CPA_STATUS_STR_INVALID_PARAM;
    case CPA_STATUS_FATAL:
        return CPA_STATUS_STR_FATAL;
    default:
        break;
    }

    return "Unknown Cpa error";
}

static inline void IntelPmInitQueue(IntelPmMatchQueue* q)
{
    q->inq = 0;
    q->inq_flush = 0;
}

static inline int IntelPmAddQueue(IntelPmMatchQueue* q, void* p)
{
    int i;

    for (i = (int)q->inq - 1; i >= 0; i--)
    {
        if (p == q->q[i])
            return 0;
    }

    if (q->inq < MAX_INQ)
        q->q[q->inq++] = p;

    if (q->inq == MAX_INQ)
        return 1;

    return 0;
}

static inline unsigned int IntelPmProcessQueue(
    IntelPmMatchQueue* q, MatchFunc match, void* data)
{
    unsigned int i;

    for (i = 0; i < q->inq; i++)
    {
        IntelPmMatchState* mstate = (IntelPmMatchState*)q->q[i];
        if (mstate != NULL)
        {
            if (match(mstate->user_data, mstate->rule_option_tree, 0, data, mstate->neg_list) > 0)
            {
                q->inq = 0;
                return 1;
            }
        }
    }

    q->inq = 0;

    return 0;
}

void IntelPmStartInstance(void)
{
    Cpa16U nInstances;
    CpaInstanceHandle instanceHandle;
    CpaInstanceHandle* pHandles;
    CpaStatus status;

    if (ipm_instance != NULL)
        return;

    status = cpaPmGetNumInstances(&nInstances);
    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmGetNumInstances() failed: %s\n", GetCpaStatusStr(status));

    pHandles = (CpaInstanceHandle*)SnortAlloc(nInstances * sizeof(CpaInstanceHandle));
    status = cpaPmGetInstances(nInstances, pHandles);
    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmGetInstances() failed: %s\n", GetCpaStatusStr(status));

    instanceHandle = pHandles[0];
    status = cpaPmStartInstance(instanceHandle);
    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmStartInstance() failed: %s\n", GetCpaStatusStr(status));

    /* Not sure if this frees everything except the first handle - taken
     * from intel code */
    free(pHandles);

    ipm_instance = instanceHandle;
}

void* IntelPmNew(
    SnortConfig* sc,
    void (* user_free)(void* p),
    void (* option_tree_free)(void** p),
    void (* neg_list_free)(void** p))
{
    CpaStatus status;
    IntelPm* ipm = (IntelPm*)SnortAlloc(sizeof(IntelPm));

    if (sc->ipm_handles == NULL)
    {
        CpaPmPdbPatternSetHandle patternSetHandle;

        status = cpaPmPdbCreatePatternSet(ipm_instance, 0, &patternSetHandle);
        if (status != CPA_STATUS_SUCCESS)
            FatalError("cpaPmPdbCreatePatternSet() failed: %s\n", GetCpaStatusStr(status));

        sc->ipm_handles = (IntelPmHandles*)SnortAlloc(sizeof(IntelPmHandles));
        sc->ipm_handles->psh = patternSetHandle;
        sc->ipm_handles->pdbh = NULL;
        sc->ipm_handles->pgids = 1;
        sc->ipm_handles->pids = 0;
        sc->ipm_handles->refs = 1;  //sc has a reference

        //memset(intel_pm_search_buf_sizes, 0, sizeof(intel_pm_search_buf_sizes));
    }

    ipm->user_free = user_free;
    ipm->option_tree_free = option_tree_free;
    ipm->neg_list_free = neg_list_free;
    ipm->match_queue = SnortAlloc(sizeof(IntelPmMatchQueue));

    ipm->handles = sc->ipm_handles;
    sc->ipm_handles->refs++;

    return (void*)ipm;
}

void IntelPmDelete(IntelPm* ipm)
{
    int i;

    if (ipm == NULL)
        return;

    if (ipm->sessionCtx != NULL)
    {
        cpaPmReleaseSessionCtx(ipm_instance, ipm->sessionCtx);
        free(ipm->sessionCtx);
        ipm->sessionCtx = NULL;
    }

    if (ipm->match_queue != NULL)
        free(ipm->match_queue);

    for (i = 0; i < ipm->pattern_array_len; i++)
    {
        IntelPmPattern* pat = &ipm->pattern_array[i];
        if (ipm->user_free && pat->user_data)
            ipm->user_free(pat->user_data);
    }

    free(ipm->pattern_array);
    IntelPmRelease(ipm->handles);
    free(ipm);
}

int IntelPmRelease(IntelPmHandles* handles)
{
    CpaStatus status;
    int i;

    if (handles == NULL)
        return -1;

    handles->refs--;
    if (handles->refs != 0)
        return handles->refs;

    for (i = 0; i < handles->pm_mtchs_len; i++)
    {
        IntelPmMatchState* ms = &handles->pm_mtchs[i];

        if (ms->rule_option_tree && ms->option_tree_free)
            ms->option_tree_free(&ms->rule_option_tree);

        if (ms->neg_list && ms->neg_list_free)
            ms->neg_list_free(&ms->neg_list);
    }

    if (handles->psh != NULL)
    {
        status = cpaPmPdbReleasePatternSet(ipm_instance, handles->psh);
        if (status != CPA_STATUS_SUCCESS)
            FatalError("cpaPmPdbReleasePatternSet() failed: %s\n", GetCpaStatusStr(status));
    }

    if (handles->pdbh != NULL)
    {
        status = cpaPmPdbRelease(ipm_instance, handles->pdbh);
        if (status != CPA_STATUS_SUCCESS)
            FatalError("cpaPmPdbRelease() failed: %s\n", GetCpaStatusStr(status));
    }

    free(handles->ipms);
    free(handles->pm_mtchs);
    free(handles);

    return 0;
}

int IntelPmAddPattern(
    SnortConfig* sc,
    IntelPm* ipm,
    const uint8_t* pat,
    unsigned pat_len,
    bool no_case,
    bool negative,
    void* pat_data,
    int pat_id)
{
    Cpa32U patternOptions = CPA_PM_PDB_OPTIONS_CASELESS | CPA_PM_PDB_OPTIONS_LITERAL;
    CpaStatus status;
    IntelPmPattern* ipp;

    if ((ipm == NULL) || (sc->ipm_handles == NULL))
        return -1;

    if (!ipm->patternGroupId)
    {
        ipm->patternGroupId = sc->ipm_handles->pgids++;
        ipm->patternIds = 1;
    }

    status = cpaPmPdbAddPattern(
        ipm_instance,
        sc->ipm_handles->psh,
        ipm->patternIds,
        patternOptions,
        pat_len,
        pat,
        ipm->patternGroupId);

    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmPdbAddPattern() failed: %s\n", GetCpaStatusStr(status));

    if (ipm->pattern_array == NULL)
    {
        ipm->pattern_array = (IntelPmPattern*)SnortAlloc(
            sizeof(IntelPmPattern) * PATTERN_ARRAY_ALLOC_SIZE);
        ipm->pattern_array_len = PATTERN_ARRAY_ALLOC_SIZE;
    }
    else if (ipm->patternIds >= ipm->pattern_array_len)
    {
        IntelPmPattern* tmp = (IntelPmPattern*)SnortAlloc(
            sizeof(IntelPmPattern) * (ipm->patternIds + PATTERN_ARRAY_ALLOC_SIZE));
        memcpy((void*)tmp, ipm->pattern_array, ipm->patternIds * sizeof(IntelPmPattern));
        free(ipm->pattern_array);
        ipm->pattern_array = tmp;
        ipm->pattern_array_len = ipm->patternIds + PATTERN_ARRAY_ALLOC_SIZE;
    }

    ipp = &ipm->pattern_array[ipm->patternIds];
    ipp->user_data = pat_data;
    ipp->rule_option_tree = NULL;
    ipp->neg_list = NULL;
    //ipp->pattern = (unsigned char *)SnortAlloc(pat_len);
    //memcpy(ipp->pattern, pat, pat_len);
    ipp->pattern = NULL;
    ipp->pattern_len = pat_len;
    ipp->no_case = no_case;
    ipp->negative = negative;
    ipp->id = pat_id;
    ipp->patternId = ipm->patternIds++;

    sc->ipm_handles->pids++;
    sc->ipm_handles->pcs += pat_len;

    return 0;
}

int IntelPmFinishGroup(
    SnortConfig* sc, IntelPm* ipm, MpseBuild build_tree, MpseNegate net_list_func)
{
    Cpa32U sessionCtxSize;
    CpaPmSessionProperty sessionProperty;
    Cpa8U* pMemory;
    CpaStatus status;

    if (ipm == NULL)
        return -1;

    ipm->build_tree = build_tree;
    ipm->neg_list_func = neg_list_func;

    sessionProperty.numPatternGroupIds = 1;
    sessionProperty.patternGroups[0].id.pdb = 0;
    sessionProperty.patternGroups[0].id.group = ipm->patternGroupId;
    sessionProperty.stateless = CPA_TRUE;

    status = cpaPmSessionCtxGetSize(ipm_instance, &sessionProperty, &sessionCtxSize);
    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmSessionCtxGetSize() failed: %s\n", GetCpaStatusStr(status));

    pMemory = (Cpa8U*)SnortAlloc(sessionCtxSize);
    status = cpaPmCreateSessionCtx(ipm_instance, &sessionProperty,
        pMemory, &ipm->sessionCtx);
    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmCreateSessionCtx() failed: %s\n", GetCpaStatusStr(status));

    if (sc->ipm_handles->ipms == NULL)
    {
        sc->ipm_handles->ipms = (IntelPm**)SnortAlloc(
            sizeof(IntelPm*) * GROUP_ARRAY_ALLOC_SIZE);
        sc->ipm_handles->ipms_len = GROUP_ARRAY_ALLOC_SIZE;
    }
    else if (ipm->patternGroupId >= sc->ipm_handles->ipms_len)
    {
        IntelPm** tmp = (IntelPm**)SnortAlloc(
            sizeof(IntelPm*) * (ipm->patternGroupId + GROUP_ARRAY_ALLOC_SIZE));
        memcpy((void*)tmp, sc->ipm_handles->ipms, sc->ipm_handles->ipms_len * sizeof(IntelPm*));
        free(sc->ipm_handles->ipms);
        sc->ipm_handles->ipms = tmp;
        sc->ipm_handles->ipms_len = ipm->patternGroupId + GROUP_ARRAY_ALLOC_SIZE;
    }

    sc->ipm_handles->ipms[ipm->patternGroupId] = ipm;

    return 0;
}

void IntelPmCompile(SnortConfig* sc)
{
    if ((ipm_instance == NULL) || (sc->ipm_handles == NULL)
        || (sc->ipm_handles->psh == NULL))
    {
        return;
    }

    if (sc->ipm_handles->pdbh == NULL)
    {
        CpaStatus status;
        Cpa16U patternGroup;
        Cpa32U numMatchStates;

        status = cpaPmPdbCompile(ipm_instance, sc->ipm_handles->psh,
            CPA_PM_COMPILE_OPTION_CONSOLIDATE, NULL, &sc->ipm_handles->pdbh);
        if (status != CPA_STATUS_SUCCESS)
            FatalError("cpaPmPdbCompile() failed: %s\n", GetCpaStatusStr(status));

        status = cpaPmMsoGetNumMatchStates(ipm_instance, sc->ipm_handles->pdbh, &numMatchStates);
        if (status != CPA_STATUS_SUCCESS)
            FatalError("cpaPmMsoGetNumMatchStates() failed: %s\n", GetCpaStatusStr(status));

        /* Hack because the last match state is returned instead of the
         * number of match states */
        numMatchStates += 1;
        sc->ipm_handles->pm_mtchs = (IntelPmMatchState*)SnortAlloc(numMatchStates *
            sizeof(IntelPmMatchState));
        sc->ipm_handles->pm_mtchs_len = numMatchStates;

        for (patternGroup = 1; patternGroup < sc->ipm_handles->pgids; patternGroup++)
        {
            CpaPmMsoMatchStateIter matchStateIter = NULL;
            Cpa32U matchStateId;
            IntelPm* ipm = sc->ipm_handles->ipms[patternGroup];

            if (ipm == NULL)
                continue;

            status = cpaPmMsoGetFirstMatchState(ipm_instance, sc->ipm_handles->pdbh,
                patternGroup, &matchStateIter, &matchStateId);

            if (status != CPA_STATUS_SUCCESS)
                FatalError("cpaPmMsoGetFirstMatchState() failed: %s\n", GetCpaStatusStr(status));

            while (matchStateIter != NULL)
            {
                CpaPmMsoPatternIdIter patternIdIter = NULL;
                Cpa32U patternID;
                IntelPmPattern* ipp = NULL;
                void* rule_option_tree = NULL;
                void* neg_list = NULL;
                void* user_data = NULL;

                status = cpaPmMsoGetFirstPatternId(ipm_instance, sc->ipm_handles->pdbh,
                    matchStateIter, &patternIdIter, &patternID);

                if (status != CPA_STATUS_SUCCESS)
                    FatalError("cpaPmMsoGetFirstPatternId() failed: %s\n", GetCpaStatusStr(
                        status));

                while (patternIdIter != NULL)
                {
                    ipp = &ipm->pattern_array[patternID];
                    if (user_data == NULL)
                        user_data = ipp->user_data;

                    if (ipp->negative)
                        ipm->neg_list_func(ipp->user_data, &neg_list);
                    else
                        ipm->build_tree(sc, ipp->user_data, &rule_option_tree);

                    status = cpaPmMsoGetNextPatternId(ipm_instance, sc->ipm_handles->pdbh,
                        &patternIdIter, &patternID);

                    if (status != CPA_STATUS_SUCCESS)
                        FatalError("cpaPmMsoGetNextPatternId() failed: %s\n", GetCpaStatusStr(
                            status));
                }

                if (ipp != NULL)
                {
                    ipm->build_tree(sc, NULL, &rule_option_tree);

                    sc->ipm_handles->pm_mtchs[matchStateId].user_data = user_data;
                    sc->ipm_handles->pm_mtchs[matchStateId].neg_list = neg_list;
                    sc->ipm_handles->pm_mtchs[matchStateId].rule_option_tree = rule_option_tree;

                    sc->ipm_handles->pm_mtchs[matchStateId].user_free = ipm->user_free;
                    sc->ipm_handles->pm_mtchs[matchStateId].option_tree_free =
                        ipm->option_tree_free;
                    sc->ipm_handles->pm_mtchs[matchStateId].neg_list_free = ipm->neg_list_free;
                }

                status = cpaPmMsoGetNextMatchState(ipm_instance, sc->ipm_handles->pdbh,
                    patternGroup, &matchStateIter, &matchStateId);

                if (status != CPA_STATUS_SUCCESS)
                    FatalError("cpaPmMsoGetNextMatchState() failed: %s\n", GetCpaStatusStr(
                        status));
            }
        }
    }
}

void IntelPmActivate(SnortConfig* sc)
{
    CpaStatus status;

    if ((ipm_instance == NULL) || (sc->ipm_handles == NULL))
        return;

    status = cpaPmActivatePdb(ipm_instance, sc->ipm_handles->pdbh, NULL);
    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmPdbActivate() failed: %s\n", GetCpaStatusStr(status));

    /* All ipms should have a reference to this now.  Need this for reloading */
    sc->ipm_handles = NULL;
}

static void IntelPmSearchCallback(const CpaInstanceHandle instanceHandle,
    CpaPmMatchCtx* pMatchCtxList)
{
    Cpa32U i;
    IntelPm* ipm = (IntelPm*)pMatchCtxList->userData;
    IntelPmHandles* handles = (IntelPmHandles*)ipm->handles;

    for (i = 0; i < pMatchCtxList->numMatchResults; i++)
    {
        CpaPmMatchResult* result = &pMatchCtxList->pMatchResult[i];

        //intel_pm_matches++;

        if (result->matchLength == 0)
            continue;

        if (result->patternGroupId.id.group != ipm->patternGroupId)
            continue;

        if (IntelPmAddQueue((IntelPmMatchQueue*)ipm->match_queue,
            (void*)&handles->pm_mtchs[result->patternId]))
        {
            IntelPmProcessQueue((IntelPmMatchQueue*)ipm->match_queue,
                ipm->match, ipm->data);
        }
    }
}

int IntelPmSearch(
    IntelPm* ipm, unsigned char* buffer, int buffer_len,
    MatchFunc match, void* data)
{
    CpaFlatBuffer flat_buffer = { buffer_len, buffer };
    CpaBufferList buffer_list = { 1, &flat_buffer, NULL, NULL };
    CpaPmMatchResult matchResults[100];  /* XXX Can this be unlimited? */
    CpaPmMatchCtx matchCtxList;
    CpaStatus status;

    //intel_pm_search_buf_sizes[buffer_len]++;

    ipm->data = data;
    ipm->match = match;

    /* Note: Search options
       CPA_PM_MATCH_OPTION_RESET_STREAM | CPA_PM_MATCH_OPTION_END_OF_STREAM
       specify a stateless search.  */

    matchCtxList.pNext = NULL;
    matchCtxList.pBufferList = &buffer_list;
    matchCtxList.sessionCtx = ipm->sessionCtx;
    matchCtxList.matchOptions = CPA_PM_MATCH_OPTION_RESET_SESSION
        | CPA_PM_MATCH_OPTION_END_OF_SESSION | CPA_PM_MATCH_OPTION_EOB_NOCALLBACK
        | CPA_PM_MATCH_OPTION_FIND_FIRST_MATCH;
    matchCtxList.matchCallback = IntelPmSearchCallback;
    matchCtxList.userData = ipm;
    matchCtxList.sizeMatchResults = DIM(matchResults);
    matchCtxList.pMatchResult = matchResults;

    status = cpaPmSearchExec(ipm_instance, &matchCtxList, NULL);
    if (status != CPA_STATUS_SUCCESS)
        FatalError("cpaPmSearchExec() failed: %s\n", GetCpaStatusStr(status));

    IntelPmProcessQueue((IntelPmMatchQueue*)ipm->match_queue,
        ipm->match, ipm->data);

    return 0;
}

int IntelGetPatternCount(IntelPm* ipm)
{
    if (ipm == NULL)
        return 0;

    return (int)ipm->patternIds;
}

int IntelPmPrintInfo(IntelPm* ipm)
{
    return 0;
}

void IntelPmPrintSummary(SnortConfig* sc)
{
    if (sc->ipm_handles == NULL)
        return;

    LogMessage("+-[Intel PM Search Info Summary]------------------\n");
    LogMessage("| Instances        : %u\n", sc->ipm_handles->pgids - 1);  /* pattern groups start
                                                                            at 1 */
    LogMessage("| Patterns         : %u\n", sc->ipm_handles->pids);
    LogMessage("| Pattern Chars    : %u\n", sc->ipm_handles->pcs);
    LogMessage("+-------------------------------------------------\n");
}

#if 0
/* XXX Temporary because Intel wants some stats on buffer sizes */
void IntelPmPrintBufferStats(void)
{
    int i;

    LogMessage(
        "===============================================================================\n");
    LogMessage("Intel stats\n\n");
    LogMessage("Number of buffers per size of buffer\n");

    for (i = 0; i < 65535; i++)
    {
        if (intel_pm_search_buf_sizes[i] > 0)
            LogMessage("%5u bytes : %7llu buffers\n", i, intel_pm_search_buf_sizes[i]);
    }

    LogMessage("\nNumber of matches: %llu\n", intel_pm_matches);
    LogMessage(
        "===============================================================================\n");
}

#endif

void IntelPmStopInstance(void)
{
    if (ipm_instance != NULL)
    {
        CpaStatus status = cpaPmStopInstance(ipm_instance);
        if (status != CPA_STATUS_SUCCESS)
            FatalError("cpaPmStopInstance() failed: %s\n", GetCpaStatusStr(status));

        ipm_instance = NULL;
    }
}

