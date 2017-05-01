//--------------------------------------------------------------------------
// Copyright (C) 2001 Marc Norton
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
/*
*  ksearch.c
*
*  Basic Keyword Search Trie - uses linked lists to build the finite automata
*
*  Keyword-Match: Performs the equivalent of a multi-string strcmp()
*     - use for token testing after parsing the language tokens using lex or the like.
*
*  Keyword-Search: searches the input text for one of multiple keywords,
*  and supports case sensitive and case insensitive patterns.
*/

#include "sfksearch.h"

#include <cassert>

#include "main/thread.h"
#include "utils/util.h"

static void KTrieFree(KTRIENODE* n);

static unsigned int mtot = 0;

unsigned int KTrieMemUsed()
{
    return mtot;
}

void KTrieInitMemUsed()
{
    mtot = 0;
}

/*
*  Allocate Memory
*/
static void* KTRIE_MALLOC(int n)
{
    assert(n > 0);
    void* p = snort_calloc(n);
    mtot += n;
    return p;
}

/*
*  Free Memory
*/
static void KTRIE_FREE(void* p)
{
    if ( p )
        snort_free(p);
}

/*
*   Local/Tmp nocase array
*/
static THREAD_LOCAL uint8_t Tnocase[65*1024];

/*
** Case Translation Table
*/
static uint8_t xlatcase[256];

/*
*
*/
void KTrie_init_xlatcase()
{
    for (int i=0; i<256; i++)
    {
        xlatcase[ i ] =  (uint8_t)tolower(i);
    }
}

/*
*
*/
static inline void ConvertCaseEx(uint8_t* d, const uint8_t* s, int m)
{
    int i;
    for ( i=0; i < m; i++ )
    {
        d[i] = xlatcase[ s[i] ];
    }
}

/*
*
*/
KTRIE_STRUCT* KTrieNew(int method, const MpseAgent* agent)
{
    KTRIE_STRUCT* ts = (KTRIE_STRUCT*)KTRIE_MALLOC(sizeof(*ts));

    ts->memory = sizeof(*ts);
    ts->nchars = 0;
    ts->npats  = 0;
    ts->end_states = 0;
    ts->method = method; /* - old method, 1 = queue */
    ts->agent = agent;

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
    if ( !k )
        return;

    KTRIEPATTERN* p = k->patrn;
    KTRIEPATTERN* pnext = nullptr;

    while ( p )
    {
        pnext = p->next;

        if (k->agent && p->user)
            k->agent->user_free(p->user);

        if (k->agent)
        {
            if (p && p->rule_option_tree)
                k->agent->tree_free(&p->rule_option_tree);
        }

        if (k->agent)
        {
            if (p && p->neg_list)
                k->agent->list_free(&p->neg_list);
        }

        KTRIE_FREE(p->P);
        KTRIE_FREE(p->Pcase);
        KTRIE_FREE(p);

        p = pnext;
    }

    for ( int i = 0; i < KTRIE_ROOT_NODES; i++ )
        KTrieFree(k->root[i]);

    KTRIE_FREE(k);
}

/*
 * Recursively delete all nodes in trie
 */
static void KTrieFree(KTRIENODE* n)
{
    if ( !n )
        return;

    KTrieFree(n->child);
    KTrieFree(n->sibling);

    KTRIE_FREE(n);
}

/*
*
*/
static KTRIEPATTERN* KTrieNewPattern(const uint8_t* P, unsigned n)
{
    if (n < 1)
        return nullptr;

    KTRIEPATTERN* p = (KTRIEPATTERN*)KTRIE_MALLOC(sizeof(*p));

    /* Save as a nocase string */
    p->P = (uint8_t*)KTRIE_MALLOC(n);

    ConvertCaseEx(p->P, P, n);

    /* Save Case specific version */
    p->Pcase = (uint8_t*)KTRIE_MALLOC(n);
    memcpy(p->Pcase, P, n);

    p->n = n;
    p->next = nullptr;

    return p;
}

/*
*  Add Pattern info to the list of patterns
*/
int KTrieAddPattern(
    KTRIE_STRUCT* ts, const uint8_t* P, unsigned n,
    bool nocase, bool negative, void* user)
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
    pnew->user = user;
    pnew->mnext = nullptr;

    ts->npats++;
    ts->memory += sizeof(KTRIEPATTERN) + 2 * n;  /* Case and nocase */

    return 0;
}

/*
*
*/
static KTRIENODE* KTrieCreateNode(KTRIE_STRUCT* ts)
{
    KTRIENODE* t = (KTRIENODE*)KTRIE_MALLOC(sizeof(*t));
    ts->memory += sizeof(*t);
    return t;
}

/*
*  Insert a Pattern in the Trie
*/
static int KTrieInsert(KTRIE_STRUCT* ts, KTRIEPATTERN* px)
{
    int type = 0;
    int n = px->n;
    uint8_t* P = px->P;
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
            else     /* cannot continue */
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
            else     /* cannot continue */
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
            *  Start a new sibling branch to finish this Keyword
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
        px->mnext = root->pkeyword;  /* insert duplicates at front of list */
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

/*
*
*/
static void Build_Bad_Character_Shifts(KTRIE_STRUCT* kt)
{
    KTRIEPATTERN* plist;

    /* Calc the min pattern size */
    kt->bcSize = 32000;

    for ( plist=kt->patrn; plist; plist=plist->next )
    {
        if ( plist->n < kt->bcSize )
        {
            kt->bcSize = plist->n; /* smallest pattern size */
        }
    }

    /*
    *  Initialize the Bad Character shift table.
    */
    for ( int i = 0; i < KTRIE_ROOT_NODES; i++ )
    {
        kt->bcShift[i] = (unsigned short)kt->bcSize;
    }

    /*
    *  Finish the Bad character shift table
    */
    for ( plist=kt->patrn; plist; plist=plist->next )
    {
        int shift, cindex;

        for ( int k=0; k<kt->bcSize; k++ )
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

static int KTrieBuildMatchStateNode(
    SnortConfig* sc, KTRIENODE* root, KTRIE_STRUCT* ts)
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
            if (p->user)
            {
                if (p->negative)
                {
                    ts->agent->negate_list(p->user, &root->pkeyword->neg_list);
                }
                else
                {
                    ts->agent->build_tree(sc, p->user, &root->pkeyword->rule_option_tree);
                }
            }

            cnt++;
        }

        /* Last call to finalize the tree for this root */
        ts->agent->build_tree(sc, nullptr, &root->pkeyword->rule_option_tree);
    }

    /* for child of this root */
    if (root->child)
    {
        cnt += KTrieBuildMatchStateNode(sc, root->child, ts);
    }

    /* 1st sibling of this root -- other siblings will be processed from
     * within the processing for root->sibling. */
    if (root->sibling)
    {
        cnt += KTrieBuildMatchStateNode(sc, root->sibling, ts);
    }

    return cnt;
}

static int KTrieBuildMatchStateTrees(SnortConfig* sc, KTRIE_STRUCT* ts)
{
    int i, cnt = 0;
    KTRIENODE* root;

    /* Find the states that have a MatchList */
    for (i = 0; i < KTRIE_ROOT_NODES; i++)
    {
        root = ts->root[i];
        /* each and every prefix match at this root*/
        if ( root and ts->agent )
        {
            cnt += KTrieBuildMatchStateNode(sc, root, ts);
        }
    }

    return cnt;
}

/*
*  Build the Keyword TRIE
*
*/
static inline int _KTrieCompile(KTRIE_STRUCT* ts)
{
    KTRIEPATTERN* p;
    /*
    static int  tmem=0;  // unused
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

    return 0;
}

int KTrieCompile(SnortConfig* sc, KTRIE_STRUCT* ts)
{
    int rval;

    if ((rval = _KTrieCompile(ts)))
        return rval;

    if ( ts->agent )
        KTrieBuildMatchStateTrees(sc, ts);

    return 0;
}

void sfksearch_print_qinfo()
{
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
static inline int KTriePrefixMatch(
    KTRIE_STRUCT* kt, const uint8_t* T, const uint8_t*, const uint8_t* bT, int n,
    MpseMatch match, void* context)
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
                index = (int)(T - bT);
                nfound++;
                if (match (pk->user, pk->rule_option_tree, index, context, pk->neg_list) > 0)
                {
                    return nfound;
                }
            }

            if ( n && root->child )
            {
                root = root->child;
            }
            else     /* cannot continue -- match is over */
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
            else     /* cannot continue */
            {
                break;
            }
        }
    }

    return nfound;
}

/*
*
*/
static inline int KTrieSearchNoBC(
    KTRIE_STRUCT* ks, const uint8_t* Tx, int n, MpseMatch match, void* context)
{
    int nfound = 0;
    const uint8_t* T, * bT;

    ConvertCaseEx(Tnocase, Tx, n);

    T  = Tnocase;
    bT = T;

    for (; n>0; n--, T++, Tx++ )
    {
        nfound += KTriePrefixMatch(ks, T, Tx, bT, n, match, context);
    }

    return nfound;
}

/*
*
*/
static inline int KTrieSearchBC(
    KTRIE_STRUCT* ks, const uint8_t* Tx, int n, MpseMatch match, void* context)
{
    int tshift;
    const uint8_t* Tend;
    const uint8_t* T, * bT;
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

        nfound += KTriePrefixMatch(ks, T, Tx, bT, n, match, context);
    }

    return nfound;
}

int KTrieSearch(
    KTRIE_STRUCT* ks, const uint8_t* T, int n, MpseMatch match, void* context)
{
    if ( ks->bcSize < 3 )
        return KTrieSearchNoBC(ks, T, n, match, context);
    else
        return KTrieSearchBC(ks, T, n, match, context);
}

// TEST DRIVER FOR KEYWORD TRIE
#ifdef KTRIE_MAIN

char** gargv;

int trie_nmatches = 0;

int match(unsigned id, int index, void* context)
{
    trie_nmatches++;
    data = context;
    printf("id=%u found at index=%d, %s\n", id, index, gargv[id]);
    return 0;
}

int main(int argc, char** argv)
{
    int i;
    KTRIE_STRUCT* ts;
    int nocase=1;  // don't care about case

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
            nocase=0;                           /* ignore case */
    }

    printf("New TRIE created\n");

    for (i=2; i<argc; i++)
    {
        if ( argv[i][0]=='-' )
            continue;

        KTrieAddPattern(ts, (uint8_t*)argv[i], strlen(argv[i]), nocase, i);
    }

    printf("Patterns added \n");

    KTrieCompile(nullptr, ts);

    printf("Patterns compiled \n");
    printf("--> %d characters, %d patterns, %d bytes allocated\n",ts->nchars,ts->npats,ts->memory);

    printf("Searching...\n");

    KTrieSearch(ts, (uint8_t*)argv[1], strlen(argv[1]), match, 0);

    printf("%d matches found\n",trie_nmatches);

    printf("normal pgm finish.\n");

    return 0;
}

#endif

