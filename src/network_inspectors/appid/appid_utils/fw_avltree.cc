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

// fw_avltree.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fw_avltree.h"

#include "utils/util.h"

static inline int is_root(FwAvlNode* node) { return (node->parent == nullptr); }
static inline int get_balance(FwAvlNode* node) { return node->balance; }
static inline void set_balance(int balance, FwAvlNode* node) { node->balance = balance; }
static inline int inc_balance(FwAvlNode* node) { return ++node->balance; }
static inline int dec_balance(FwAvlNode* node) { return --node->balance; }
static inline FwAvlNode* get_parent(FwAvlNode* node) { return node->parent; }

static inline void set_parent(FwAvlNode* parent, FwAvlNode* node)
{
    node->parent = parent;
}

static inline FwAvlNode* new_node(uint32_t key, void* data)
{
    FwAvlNode* node = (FwAvlNode*)snort_calloc(sizeof(FwAvlNode));

    node->key = key;
    node->data = data;
    return node;
}

static inline FwAvlNode* get_first(FwAvlNode* node)
{
    while (node->left != nullptr)
        node = node->left;
    return node;
}

static inline FwAvlNode* get_last(FwAvlNode* node)
{
    while (node->right != nullptr)
        node = node->right;
    return node;
}

FwAvlNode* fwAvlFirst(const FwAvlTree* tree)
{
    if ((tree != nullptr) && (tree->root != nullptr))
        return get_first(tree->root);
    else
        return nullptr;
}

FwAvlNode* fwAvlLast(const FwAvlTree* tree)
{
    if ((tree != nullptr) && (tree->root != nullptr))
        return get_last(tree->root);
    else
        return nullptr;
}

FwAvlNode* fwAvlNext(FwAvlNode* node)
{

    if (node->right != nullptr)
    {
        return get_first(node->right);
    }
    else
    {
        FwAvlNode* parent = nullptr;
        FwAvlNode* tmp = node;
        while ( ((parent = get_parent(tmp)) != nullptr) && (parent->right == tmp) )
            tmp = parent;

        return parent;
    }
}

FwAvlNode* fwAvlPrev(FwAvlNode* node)
{
    FwAvlNode* parent;
    FwAvlNode* tmp;

    if (node->left != nullptr)
    {
        tmp = get_first(node->left);
    }
    else
    {
        tmp = node;
        while ( ((parent = get_parent(tmp)) != nullptr) && (parent->left == tmp) )
            tmp = parent;
    }
    return tmp;
}

static void rotate_left(FwAvlNode* node, FwAvlTree* tree)
{
    FwAvlNode* p = node;
    FwAvlNode* q = node->right;
    FwAvlNode* parent = get_parent(node);

    if (!is_root(p))
    {
        if (parent->left == p)
            parent->left = q;
        else
            parent->right = q;
    }
    else
    {
        tree->root = q;
    }

    set_parent(parent, q);
    set_parent(q, p);

    p->right = q->left;
    if (p->right != nullptr)
    {
        set_parent(p, p->right);
    }
    q->left = p;
}

static void rotate_right(FwAvlNode* node, FwAvlTree* tree)
{
    FwAvlNode* p = node;
    FwAvlNode* q = node->left;
    FwAvlNode* parent = get_parent(node);

    if (!is_root(p))
    {
        if (parent->left == p)
            parent->left = q;
        else
            parent->right = q;
    }
    else
    {
        tree->root = q;
    }

    set_parent(parent, q);
    set_parent(q, p);

    p->left = q->right;
    if (p->left != nullptr)
    {
        set_parent(p, p->left);
    }
    q->right = p;
}

static inline FwAvlNode* do_lookup(const uint32_t key,
    const FwAvlTree* tree, FwAvlNode** pparent,
    FwAvlNode** unbalanced, int* is_left)
{
    FwAvlNode* node = tree->root;

    *pparent = nullptr;
    *unbalanced = node;
    *is_left = 0;

    while (node != nullptr)
    {
        if (get_balance(node) != 0)
        {
            *unbalanced = node;
        }

        *pparent = node;

        if (key == node->key)
        {
            return node;
        }
        else
        {
            if ((*is_left = node->key > key) != 0)
                node = node->left;
            else
                node = node->right;
        }
    }
    return nullptr;
}

void* fwAvlLookup(const uint32_t key, const FwAvlTree* tree)
{
    FwAvlNode* node = nullptr;
    FwAvlNode* pparent;
    FwAvlNode* unbalanced;
    int is_left;

    if (tree == nullptr)
    {
        return nullptr;
    }

    node = do_lookup(key, tree, &pparent, &unbalanced, &is_left);

    if (node != nullptr)
    {
        return node->data;
    }

    return nullptr;
}

static inline void set_child(FwAvlNode* child, FwAvlNode* node,
    int left)
{
    if (left != 0)
        node->left = child;
    else
        node->right = child;
}

int fwAvlInsert(uint32_t key, void* data, FwAvlTree* tree)
{
    int is_left;
    FwAvlNode* parent;
    FwAvlNode* right;
    FwAvlNode* left;
    FwAvlNode* unbalanced;
    FwAvlNode* node;

    if (do_lookup(key, tree, &parent, &unbalanced, &is_left) != nullptr)
        return 1;

    if (!(node = new_node(key, data)))
        return -1;

    tree->count++;
    if (parent == nullptr)
    {
        tree->root = node;
        tree->first = node;
        tree->last = node;
        return 0;
    }

    if (is_left != 0)
    {
        if (parent == tree->first)
            tree->first = node;
    }
    else
    {
        if (parent == tree->last)
            tree->last = node;
    }
    set_parent(parent, node);
    set_child(node, parent, is_left);

    for (;; )
    {
        if (parent->left == node)
            dec_balance(parent);
        else
            inc_balance(parent);

        if (parent == unbalanced)
            break;

        node = parent;
        parent = get_parent(node);
    }

    switch (get_balance(unbalanced))
    {
    case 1:
    case -1:
        tree->height++;
        break;
    case 0:
        break;
    case 2:
        right = unbalanced->right;

        if (get_balance(right) == 1)
        {
            set_balance(0, unbalanced);
            set_balance(0, right);
        }
        else
        {
            switch (get_balance(right->left))
            {
            case 1:
                set_balance(-1, unbalanced);
                set_balance(0, right);
                break;
            case 0:
                set_balance(0, unbalanced);
                set_balance(0, right);
                break;
            case -1:
                set_balance(0, unbalanced);
                set_balance(1, right);
                break;
            }
            set_balance(0, right->left);
            rotate_right(right, tree);
        }
        rotate_left(unbalanced, tree);
        break;
    case -2:
        left = unbalanced->left;

        if (get_balance(left) == -1)
        {
            set_balance(0, unbalanced);
            set_balance(0, left);
        }
        else
        {
            switch (get_balance(left->right))
            {
            case 1:
                set_balance(0, unbalanced);
                set_balance(-1, left);
                break;
            case 0:
                set_balance(0, unbalanced);
                set_balance(0, left);
                break;
            case -1:
                set_balance(1, unbalanced);
                set_balance(0, left);
                break;
            }
            set_balance(0, left->right);
            rotate_left(left, tree);
        }
        rotate_right(unbalanced, tree);
        break;
    }
    return 0;
}

FwAvlTree* fwAvlInit()
{
    return (FwAvlTree*)snort_calloc(sizeof(FwAvlTree));
}

static FwQNode* newFwQNode(FwAvlNode* treeNode)
{
    FwQNode* q_node = (FwQNode*)snort_calloc(sizeof(FwQNode));

    q_node->treeNode = treeNode;
    q_node->next = nullptr;
    return(q_node);
}

FwQNode* fwAvlSerialize(FwAvlTree* tree)
{
    FwQNode* head;
    FwQNode* node;
    FwQNode* tail;

    if ((tree == nullptr) || (tree->root == nullptr))
        return nullptr;

    head = newFwQNode(tree->root);
    node = head;
    tail = head;

    while (node)
    {
        if (node->treeNode->left != nullptr)
        {
            tail->next = newFwQNode(node->treeNode->left);
            tail = tail->next;
        }

        if (node->treeNode->right != nullptr)
        {
            tail->next = newFwQNode(node->treeNode->right);
            tail = tail->next;
        }

        node = node->next;
    }
    return head;
}

void fwAvlDeleteTree(FwAvlTree* tree, void (* dataDelete)(void* data))
{
    FwQNode* node = fwAvlSerialize(tree);

    while (node != nullptr)
    {
        if (dataDelete)
            dataDelete(node->treeNode->data);

        snort_free(node->treeNode);

        FwQNode* tmp = node;
        node = node->next;
        snort_free(tmp);
    }
    snort_free(tree);
}

