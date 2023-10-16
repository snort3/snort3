//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// kmap.cc author Marc Norton
// a generic map library - maps key + data pairs

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "kmap.h"

#include <cassert>
#include <string>

#include "util.h"

namespace snort
{
KMAP* KMapNew(KMapUserFreeFunc userfree, bool nc)
{
    KMAP* km = (KMAP*)snort_calloc(sizeof(KMAP));
    km->userfree = userfree;
    km->nocase = nc;
    return km;
}

static int KMapFreeNodeList(KMAP* km)
{
    for ( KEYNODE* k=km->keylist; k; )
    {
        if ( k->key )
            snort_free(k->key);

        if ( km->userfree && k->userdata )
            km->userfree(k->userdata);

        KEYNODE* kold = k;
        k = k->next;
        snort_free(kold);
    }

    return 0;
}

static void KMapFreeNode(KMAP* km, KMAPNODE* r)
{
    if ( r->sibling )
        KMapFreeNode(km, r->sibling);

    if ( r->child )
        KMapFreeNode(km, r->child);

    snort_free(r);
}

void KMapDelete(KMAP* km)
{
    for (int i=0; i<256; i++)
    {
        KMAPNODE* r = km->root[i];

        if ( r )
            KMapFreeNode(km,r);

        km->root[i] = nullptr;
    }

    KMapFreeNodeList(km);
    snort_free(km);
}

static KEYNODE* KMapAddKeyNode(KMAP* km,void* key, int n, void* userdata)
{
    KEYNODE* knode;

    if (n <= 0)
        return nullptr;

    knode = (KEYNODE*)snort_calloc(sizeof(KEYNODE));
    knode->key = (unsigned char*)snort_calloc(n);

    memcpy(knode->key, key, n);
    knode->nkey = n;
    knode->userdata = userdata;

    if ( km->keylist )
    {
        knode->next = km->keylist;
        km->keylist = knode;
    }
    else
    {
        km->keylist = knode;
    }

    return knode;
}

static KMAPNODE* KMapCreateNode(KMAP* km)
{
    KMAPNODE* mn=(KMAPNODE*)snort_calloc(sizeof(KMAPNODE));
    km->nchars++;
    return mn;
}

/*
*    key : ptr to bytes of data used to identify this item
*          may be text string, or binary character sequence.
*    n   : > 0 number of bytes in the key
*    userdata - ptr to data to associate with this key
*
*   returns:
*            -1 - no memory
*             1 - key already in table
*             0 - key added successfully
*/
int KMapAdd(KMAP* km, void* key, int n, void* userdata)
{
    assert(n > 0);

    int type = 0;
    const unsigned char* P = (unsigned char*)key;
    std::string xkey;

    if ( km->nocase )
    {
        xkey.resize(n);

        for (int i=0; i<n; i++)
            xkey[i] = std::tolower(P[i]);

        P = (const unsigned char*)xkey.c_str();
    }

    int ksize = n;
    KMAPNODE* root;

    //printf("adding key='%.*s'\n",n,P);

    /* Make sure we at least have a root character for the tree */
    if ( !km->root[ *P ] )
    {
        root = KMapCreateNode(km);
        km->root[ *P ] = root;
        root->nodechar = *P;
    }
    else
    {
        root = km->root[ *P ];
    }

    /* Walk existing Patterns */
    while ( n )
    {
        if ( root->nodechar == *P )
        {
            //printf("matched char = %c, nleft = %d\n",*P,n-1);
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
            //printf("added child branch nodechar = %c \n",*P);
            root->child= KMapCreateNode(km);
            root=root->child;
            root->nodechar  = *P;
            P++;
            n--;
        }
        else
        {
            /*
            *  Start a new sibling branch to finish this Keyword
                */
            //printf("added sibling branch nodechar = %c \n",*P);
            root->sibling= KMapCreateNode(km);
            root=root->sibling;
            root->nodechar  = *P;
            P++;
            n--;
        }
    }

    /*
    *    Finish the keyword as child nodes
    */
    while ( n )
    {
        //printf("added child nodechar = %c \n",*P);
        root->child = KMapCreateNode(km);
        root=root->child;
        root->nodechar  = *P;
        P++;
        n--;
    }

    /*
    * Iteration support - Add this key/data to the linked list
    * This allows us to do a findfirst/findnext search of
    * all map nodes.
    */
    if ( root->knode ) /* Already present */
        return 1;

    root->knode = KMapAddKeyNode(km, key, ksize, userdata);

    return 0;
}

/*
*  Exact Keyword Match - unique keys, with just one piece of
*  'userdata' , for multiple entries, we could use a list
*  of 'userdata' nodes.
*/
void* KMapFind(KMAP* ks, void* key, int n)
{
    assert(n > 0);

    std::string xkey;
    const unsigned char* T = (unsigned char*)key;

    if ( ks->nocase )
    {
        xkey.resize(n);

        for (int i=0; i<n; i++)
            xkey[i] = std::tolower(T[i]);

        T = (const unsigned char*)xkey.c_str();
    }
    //printf("finding key='%.*s'\n",n,T);

    /* Check if any keywords start with this character */
    KMAPNODE* root = ks->root[ *T ];
    if ( !root )
        return nullptr;

    while ( n )
    {
        if ( root->nodechar == *T )
        {
            T++;
            n--;
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

    if ( !n )
    {
        if (root && root->knode)
            return root->knode->userdata; /* success */
    }

    return nullptr;
}

void* KMapFindFirst(KMAP* km)
{
    km->keynext = km->keylist;

    if (!km->keynext)
        return nullptr;

    return km->keynext->userdata;
}

void* KMapFindNext(KMAP* km)
{
    if ( !km->keynext )
        return nullptr;

    km->keynext = km->keynext->next;

    if ( !km->keynext )
        return nullptr;

    return km->keynext->userdata;
}

} //namespace snort

