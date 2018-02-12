//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// fw_avltree.h author Sourcefire Inc.

#ifndef FW_AVL_TREE_H
#define FW_AVL_TREE_H

#include <cstddef>
#include <cstdint>

struct FwAvlNode
{
    uint32_t key;
    void* data;
    int balance;
    FwAvlNode* left;
    FwAvlNode* right;
    FwAvlNode* parent;
};

struct FwAvlTree
{
    unsigned count;
    size_t height;
    FwAvlNode* root;
    FwAvlNode* first;
    FwAvlNode* last;
};

struct FwQNode
{
    FwAvlNode* treeNode;
    FwQNode* next;
};

FwAvlTree* fwAvlInit();
int fwAvlInsert(uint32_t key, void* data, FwAvlTree*);
void* fwAvlLookup(const uint32_t key, const FwAvlTree*);
FwAvlNode* fwAvlFirst(const FwAvlTree*);
FwAvlNode* fwAvlLast(const FwAvlTree*);
FwAvlNode* fwAvlNext(FwAvlNode*);
FwAvlNode* fwAvlPrev(FwAvlNode*);
FwQNode* fwAvlSerialize(FwAvlTree*);
void fwAvlDeleteTree(FwAvlTree*, void (* dataDelete)(void* data));

#endif

