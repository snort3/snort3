//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// sfksearch.cc author Sourcefire Inc.

/*
*
*  Basic Keyword Search Trie - uses linked lists to build the finite automata
*
*  Keyword-Match: Performs the equivalent of a multi-string strcmp()
*     - use for token testing after parsing the language tokens using lex or the like.
*
*  Keyword-Search: searches the input text for one of multiple keywords,
*  and supports case sensitivite and case insensitive patterns.
*
*/

#include "sfksearch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "utils/util.h"

static void KTrieFree(KTRIENODE* n);

static unsigned int mtot = 0;

unsigned int KTrieMemUsed(void) { return mtot; }

void KTrieInitMemUsed(void)
{
    mtot = 0;
}

/*
*  Allocate Memory
*/
static void* KTRIE_MALLOC(int n)
{
    void* p;

    if (n < 1)
        return nullptr;

    p = snort_calloc(n);
    mtot += n;

    return p;
}

/*
*  Free Memory
*/
static void KTRIE_FREE(void* p)
{
    if (p == nullptr)
        return;

    snort_free(p);
}

/*
*   Local/Tmp nocase array
*/
static unsigned char Tnocase[65*1024];

/*
** Case Translation Table
*/
static unsigned char xlatcase[256];

static void init_xlatcase(void)
{
    int i;
    static int first=1;

    if ( !first )
        return;         /* thread safe */

    for (i=0; i<256; i++)
    {
        xlatcase[ i ] =  (unsigned char)tolower(i);
    }

    first=0;
}

static inline void ConvertCaseEx(unsigned char* d, const unsigned char* s, int m)
{
    int i;
    for ( i=0; i < m; i++ )
    {
        d[i] = xlatcase[ s[i] ];
    }
}

KTRIE_STRUCT* KTrieNew(int method, void (* userfree)(void* p),
    void (* optiontreefree)(void** p),
    void (* neg_list_free)(void** p))
{
    KTRIE_STRUCT* ts = (KTRIE_STRUCT*)KTRIE_MALLOC(sizeof(KTRIE_STRUCT) );

    if ( !ts )
        return 0;

    memset(ts, 0, sizeof(KTRIE_STRUCT));

    init_xlatcase();

    ts->memory = sizeof(KTRIE_STRUCT);
    ts->nchars = 0;
    ts->npats  = 0;
    ts->end_states = 0;
    ts->method = method; /* - old method, 1 = queue */
    ts->userfree = userfree;
    ts->optiontreefree = optiontreefree;
    ts->neg_list_free = neg_list_free;

    return ts;
}

int KTriePatternCount(KTRIE_STRUCT* k)
{
    return k->npats;
}

/*
 * Deletes memory that was used in creating trie
 * and nodes
 */
void KTrieDelete(KTRIE_STRUCT* k)
{
    KTRIEPATTERN* p = nullptr;
    KTRIEPATTERN* pnext = nullptr;
    int i;

    if (k == nullptr)
        return;

    p = k->patrn;

    while (p != nullptr)
    {
        pnext = p->next;

        if (k->userfree && p->id)
            k->userfree(p->id);

        if (k->optiontreefree)
        {
            if (p && p->rule_option_tree)
                k->optiontreefree(&p->rule_option_tree);
        }

        if (k->neg_list_free)
        {
            if (p && p->neg_list)
                k->neg_list_free(&p->neg_list);
        }

        KTRIE_FREE(p->P);
        KTRIE_FREE(p->Pcase);
        KTRIE_FREE(p);

        p = pnext;
    }

    for (i = 0; i < KTRIE_ROOT_NODES; i++)
        KTrieFree(k->root[i]);

    KTRIE_FREE(k);
}

/*
 * Recursively delete all nodes in trie
 */
static void KTrieFree(KTRIENODE* n)
{
    if (n == nullptr)
        return;

    KTrieFree(n->child);
    KTrieFree(n->sibling);

    KTRIE_FREE(n);
}

static KTRIEPATTERN* KTrieNewPattern(unsigned char* P, int n)
{
    KTRIEPATTERN* p;

    if (n < 1)
        return nullptr;

    p = (KTRIEPATTERN*)KTRIE_MALLOC(sizeof(KTRIEPATTERN) );

    if (p == nullptr)
        return nullptr;

    /* Save as a nocase string */
    p->P = (unsigned char*)KTRIE_MALLOC(n);
    if ( !p->P )
    {
        KTRIE_FREE(p);
        return nullptr;
    }

    ConvertCaseEx(p->P, P, n);

    /* Save Case specific version */
    p->Pcase = (unsigned char*)KTRIE_MALLOC(n);
    if ( !p->Pcase )
    {
        KTRIE_FREE(p->P);
        KTRIE_FREE(p);
        return nullptr;
    }

    memcpy(p->Pcase, P, n);

    p->n    = n;
    p->next = nullptr;

    return p;
}

/*
*  Add Pattern info to the list of patterns
*/
int KTrieAddPattern(KTRIE_STRUCT* ts, unsigned char* P, int n,
    int nocase, int negative, void* id)
{
    KTRIEPATTERN* pnew;

    if ( !ts->patrn )
    {
        pnew = ts->patrn = KTrieNewPattern(P, n);

        if ( !pnew )
            return -1;
    }
    else
    {
        pnew = KTrieNewPattern(P, n);

        if ( !pnew )
            return -1;

        pnew->next = ts->patrn; /* insert at head of list */

        ts->patrn = pnew;
    }

    pnew->nocase = nocase;
    pnew->negative = negative;
    pnew->id     = id;
    pnew->mnext  = nullptr;

    ts->npats++;
    ts->memory += sizeof(KTRIEPATTERN) + 2 * n; /* Case and nocase */

    return 0;
}

static KTRIENODE* KTrieCreateNode(KTRIE_STRUCT* ts)
{
    KTRIENODE* t=(KTRIENODE*)KTRIE_MALLOC(sizeof(KTRIENODE) );

    if (!t)
        return 0;

    memset(t,0,sizeof(KTRIENODE));

    ts->memory += sizeof(KTRIENODE);

    return t;
}

/*
*  Insert a Pattern in the Trie
*/
static int KTrieInsert(KTRIE_STRUCT* ts, KTRIEPATTERN* px)
{
    int type = 0;
    int n = px->n;
    unsigned char* P = px->P;
    KTRIENODE* root;

    /* Make sure we at least have a root character for the tree */
    if ( !ts->root[*P] )
    {
        ts->root[*P] = root = KTrieCreateNode(ts);
        if ( !root )
            return -1;
        root->edge = *P;
    }
    else
    {
        root = ts->root[*P];
    }

    /* Walk existing Patterns */
    while ( n )
    {
        if ( root->edge == *P )
        {
            P++;
            n--;

            if ( n && root->child )
            {
                root=root->child;
            }
            else /* cannot continue */
            {
                type = 0; /* Expand the tree via the child */
                break;
            }
        }
        else
        {
            if ( root->sibling )
            {
                root=root->sibling;
            }
            else /* cannot continue */
            {
                type = 1; /* Expand the tree via the sibling */
                break;
            }
        }
    }

    /*
    * Add the next char of the Keyword, if any
    */
    if ( n )
    {
        if ( type == 0 )
        {
            /*
            *  Start with a new child to finish this Keyword
            */
            root->child= KTrieCreateNode(ts);
            if ( !root->child )
                return -1;
            root=root->child;
            root->edge  = *P;
            P++;
            n--;
            ts->nchars++;
        }
        else
        {
            /*
            *  Start a new sibling bracnch to finish this Keyword
            */
            root->sibling= KTrieCreateNode(ts);
            if ( !root->sibling )
                return -1;
            root=root->sibling;
            root->edge  = *P;
            P++;
            n--;
            ts->nchars++;
        }
    }

    /*
    *    Finish the keyword as child nodes
    */
    while ( n )
    {
        root->child = KTrieCreateNode(ts);
        if ( !root->child )
            return -1;
        root=root->child;
        root->edge  = *P;
        P++;
        n--;
        ts->nchars++;
    }

    if ( root->pkeyword )
    {
        px->mnext = root->pkeyword; /* insert duplicates at front of list */
        root->pkeyword = px;
        ts->duplicates++;
    }
    else
    {
        root->pkeyword = px;
        ts->end_states++;
    }

    return 0;
}

static void Build_Bad_Character_Shifts(KTRIE_STRUCT* kt)
{
    int i,k;
    KTRIEPATTERN* plist;

    /* Calc the min pattern size */
    kt->bcSize = 32000;

    for ( plist=kt->patrn; plist!=nullptr; plist=plist->next )
    {
        if ( plist->n < kt->bcSize )
        {
            kt->bcSize = plist->n; /* smallest pattern size */
        }
    }

    /*
    *  Initialze the Bad Character shift table.
    */
    for (i = 0; i < KTRIE_ROOT_NODES; i++)
    {
        kt->bcShift[i] = (unsigned short)kt->bcSize;
    }

    /*
    *  Finish the Bad character shift table
    */
    for ( plist=kt->patrn; plist!=nullptr; plist=plist->next )
    {
        int shift, cindex;

        for ( k=0; k<kt->bcSize; k++ )
        {
            shift = kt->bcSize - 1 - k;

            cindex = plist->P[ k ];

            if ( shift < kt->bcShift[ cindex ] )
            {
                kt->bcShift[ cindex ] = (unsigned short)shift;
            }
        }
    }
}

static int KTrieBuildMatchStateNode(KTRIENODE* root,
    int (* build_tree)(void* id, void** existing_tree),
    int (* neg_list_func)(void* id, void** list))
{
    int cnt = 0;
    KTRIEPATTERN* p;

    if (!root)
        return 0;

    /* each and every prefix match at this root*/
    if (root->pkeyword)
    {
        for (p = root->pkeyword; p; p = p->mnext)
        {
            if (p->id)
            {
                if (p->negative)
                {
                    neg_list_func(p->id, &root->pkeyword->neg_list);
                }
                else
                {
                    build_tree(p->id, &root->pkeyword->rule_option_tree);
                }
            }

            cnt++;
        }

        /* Last call to finalize the tree for this root */
        build_tree(nullptr, &root->pkeyword->rule_option_tree);
    }

    /* for child of this root */
    if (root->child)
    {
        cnt += KTrieBuildMatchStateNode(root->child, build_tree, neg_list_func);
    }

    /* 1st sibling of this root -- other siblings will be processed from
     * within the processing for root->sibling. */
    if (root->sibling)
    {
        cnt += KTrieBuildMatchStateNode(root->sibling, build_tree, neg_list_func);
    }

    return cnt;
}

static int KTrieBuildMatchStateTrees(KTRIE_STRUCT* ts,
    int (* build_tree)(void* id, void** existing_tree),
    int (* neg_list_func)(void* id, void** list))
{
    int i, cnt = 0;
    KTRIENODE* root;

    /* Find the states that have a MatchList */
    for (i = 0; i < KTRIE_ROOT_NODES; i++)
    {
        root = ts->root[i];
        /* each and every prefix match at this root*/
        if (root)
        {
            cnt += KTrieBuildMatchStateNode(root, build_tree, neg_list_func);
        }
    }

    return cnt;
}

/*
*  Build the Keyword TRIE
*
*/
int KTrieCompile(KTRIE_STRUCT* ts,
    int (* build_tree)(void* id, void** existing_tree),
    int (* neg_list_func)(void* id, void** list))
{
    KTRIEPATTERN* p;
    /*
    static int  tmem=0;
    */

    /*
    *    Build the Keyword TRIE
    */
    for ( p=ts->patrn; p; p=p->next )
    {
        if ( KTrieInsert(ts, p) )
            return -1;
    }

    /*
    *    Build A Setwise Bad Character Shift Table
    */
    Build_Bad_Character_Shifts(ts);

    /*
    tmem += ts->memory;
    printf(" Compile stats: %d patterns, %d chars, %d duplicate patterns, %d bytes, %d total-bytes\n",ts->npats,ts->nchars,ts->duplicates,ts->memory,tmem);
    */
    if (build_tree && neg_list_func)
    {
        KTrieBuildMatchStateTrees(ts, build_tree, neg_list_func);
    }

    return 0;
}

void sfksearch_print_qinfo(void)
{
#ifdef SFKSEARCH_TRACK_Q
    if ( snort_conf->max_inq )
    {
        LogMessage("lowmem: queue size     = %u, max  = %u\n", snort_conf->max_inq,SFK_MAX_INQ);
        LogMessage("lowmem: queue flushes  = " STDu64 "\n", snort_conf->tot_inq_flush);
        LogMessage("lowmem: queue inserts  = " STDu64 "\n", snort_conf->tot_inq_inserts);
        LogMessage("lowmem: queue uinserts = " STDu64 "\n", snort_conf->tot_inq_uinserts);
    }
#endif
}

static inline void _init_queue(SFK_PMQ* b)
{
    b->inq=0;
    b->inq_flush=0;
}

/* uniquely insert into q */
static inline int _add_queue(SFK_PMQ* b, KTRIEPATTERN* p)
{
    int i;

#ifdef SFKSEARCH_TRACK_Q
    snort_conf->tot_inq_inserts++;
#endif

    for (i=(int)(b->inq)-1; i>=0; i--)
        if ( p == b->q[i] )
            return 0;

#ifdef SFKSEARCH_TRACK_Q
    snort_conf->tot_inq_uinserts++;
#endif

    if ( b->inq < SFK_MAX_INQ )
    {
        b->q[ b->inq++ ] = p;
    }

    if ( b->inq == SFK_MAX_INQ )
    {
#ifdef SFKSEARCH_TRACK_Q
        b->inq_flush++;
#endif
        return 1;
    }
    return 0;
}

static inline unsigned _process_queue(SFK_PMQ* q,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data)
{
    KTRIEPATTERN* pk;
    unsigned int i;

#ifdef SFKSEARCH_TRACK_Q
    if ( q->inq > snort_conf->max_inq )
        snort_conf->max_inq = q->inq;
    snort_conf->tot_inq_flush += q->inq_flush;
#endif

    for ( i=0; i<q->inq; i++ )
    {
        pk = q->q[i];
        if (pk)
        {
            if (match (pk->id, pk->rule_option_tree, 0, data, pk->neg_list) > 0)
            {
                q->inq=0;
                return 1;
            }
        }
    }
    q->inq=0;
    return 0;
}

static inline int KTriePrefixMatchQ(KTRIE_STRUCT* kt,
    const unsigned char* T,
    int n,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data)
{
    KTRIENODE* root;

    root   = kt->root[ xlatcase[*T] ];

    if ( !root )
        return 0;

    while ( n )
    {
        if ( root->edge == xlatcase[*T] )
        {
            T++;
            n--;

            if ( root->pkeyword )
            {
                if ( _add_queue(&kt->q, root->pkeyword) )
                {
                    if ( _process_queue(&kt->q,match,data) )
                    {
                        return 1;
                    }
                }
            }

            if ( n && root->child )
            {
                root = root->child;
            }
            else /* cannot continue -- match is over */
            {
                break;
            }
        }
        else
        {
            if ( root->sibling )
            {
                root = root->sibling;
            }
            else /* cannot continue */
            {
                break;
            }
        }
    }

    return 0;
}

/*
*   Search - Algorithm
*
*   This routine will log any substring of T that matches a keyword,
*   and processes all prefix matches. This is used for generic
*   pattern searching with a set of keywords and a body of text.
*
*
*
*   kt- Trie Structure
*   T - nocase text
*   Tc- case specific text
*   n - text length
*
*   returns:
*   # pattern matches
*/
static inline int KTriePrefixMatch(KTRIE_STRUCT* kt,
    const unsigned char* T,
    const unsigned char*,
    const unsigned char* bT,
    int n,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data)
{
    KTRIENODE* root   = kt->root[ *T ];
    int nfound = 0;
    KTRIEPATTERN* pk;
    int index;

    /* Check if any keywords start with this character */
    if ( !root )
        return 0;

    while ( n )
    {
        if ( root->edge == *T )
        {
            T++;
            n--;

            pk = root->pkeyword;
            if (pk)
            {
                index = (int)(T - bT - pk->n );
                nfound++;
                if (match (pk->id, pk->rule_option_tree, index, data, pk->neg_list) > 0)
                {
                    return nfound;
                }
            }

            if ( n && root->child )
            {
                root = root->child;
            }
            else /* cannot continue -- match is over */
            {
                break;
            }
        }
        else
        {
            if ( root->sibling )
            {
                root = root->sibling;
            }
            else /* cannot continue */
            {
                break;
            }
        }
    }

    return nfound;
}

static inline int KTrieSearchQ(KTRIE_STRUCT* ks, const unsigned char* T, int n,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data)
{
    _init_queue(&ks->q);
    while ( n > 0 )
    {
        if ( KTriePrefixMatchQ(ks, T++, n--, match, data) )
            return 0;
    }
    _process_queue(&ks->q,match,data);

    return 0;
}

static inline int KTrieSearchNoBC(KTRIE_STRUCT* ks, const unsigned char* Tx,
    int n,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data)
{
    int nfound = 0;
    const unsigned char* T, * bT;

    ConvertCaseEx(Tnocase, Tx, n);

    T  = Tnocase;
    bT = T;

    for (; n>0; n--, T++, Tx++ )
    {
        nfound += KTriePrefixMatch(ks, T, Tx, bT, n, match, data);
    }

    return nfound;
}

static inline int KTrieSearchBC(KTRIE_STRUCT* ks, const unsigned char* Tx,
    int n,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data)
{
    int tshift;
    const unsigned char* Tend;
    const unsigned char* T, * bT;
    int nfound  = 0;
    short* bcShift = (short*)ks->bcShift;
    int bcSize  = ks->bcSize;

    ConvertCaseEx(Tnocase, Tx, n);

    T  = Tnocase;
    bT = T;

    Tend = T + n - bcSize;

    bcSize--;

    for (; T <= Tend; n--, T++, Tx++ )
    {
        while ( (tshift = bcShift[ *( T + bcSize ) ]) > 0 )
        {
            T  += tshift;
            Tx += tshift;
            if ( T > Tend )
                return nfound;
        }

        nfound += KTriePrefixMatch(ks, T, Tx, bT, n, match, data);
    }

    return nfound;
}

int KTrieSearch(KTRIE_STRUCT* ks, const unsigned char* T, int n,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data)
{
    if ( ks->method == KTRIEMETHOD_QUEUE )
    {
        /*if( ks->bcSize < 3) */
        return KTrieSearchQ(ks, T, n, match, data);
        /*else
           return KTrieSearchQBC( ks, T, n, match, data ); */
    }
    else
    {
        if ( ks->bcSize < 3)
            return KTrieSearchNoBC(ks, T, n, match, data);
        else
            return KTrieSearchBC(ks, T, n, match, data);
    }
}

/*
*
*    TEST DRIVER FOR KEYWORD TRIE
*
*/
#ifdef KTRIE_MAIN

char** gargv;

int trie_nmatches = 0;

int match(unsigned id, int index, void* data)
{
    trie_nmatches++;
    data = data;
    printf("id=%d found at index=%d, %s\n",id,index,gargv[id]);
    return 0;
}

int main(int argc, char** argv)
{
    int i;
    KTRIE_STRUCT* ts;
    int nocase=1;  /* don't care about case */

    gargv = argv;

    ts = KTrieNew();

    if ( argc < 3 )
    {
        printf("%s text pat1 pat2 ... patn [-c(ase-sensitive)\n",argv[0]);
        printf("search for keywords-default, or match keywords\n");
        exit(0);
    }

    for (i=1; i<argc; i++)
    {
        if ( strcmp(argv[i],"-c")==0 )
            nocase=0;                          /* ignore case */
    }

    printf("New TRIE created\n");

    for (i=2; i<argc; i++)
    {
        if ( argv[i][0]=='-' )
            continue;

        KTrieAddPattern(ts, (unsigned char*)argv[i], strlen(argv[i]), nocase, i);
    }

    printf("Patterns added \n");

    KTrieCompile(ts);

    printf("Patterns compiled \n");
    printf("--> %d characters, %d patterns, %d bytes allocated\n",ts->nchars,ts->npats,ts->memory);

    printf("Searching...\n");

    KTrieSearch(ts, (unsigned char*)argv[1], strlen(argv[1]), match, 0);

    printf("%d matches found\n",trie_nmatches);

    printf("normal pgm finish.\n");

    return 0;
}

#endif

