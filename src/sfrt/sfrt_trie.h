//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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
   trie.h

   A routing table for wordsized (32bits) bitstrings implemented as a
   static level- and pathcompressed trie. For details please consult

      Stefan Nilsson and Gunnar Karlsson. Fast Address Look-Up
      for Internet Routers. International Conference of Broadband
      Communications (BC'97).

      http://www.hut.fi/~sni/papers/router/router.html

   The code presented in this file has been tested with care but is
   not guaranteed for any purpose. The writer does not offer any
   warranties nor does he accept any liabilities with respect to
   the code.

   Stefan Nilsson, 4 nov 1997.

   Laboratory of Information Processing Science
   Helsinki University of Technology
   Stefan.Nilsson@hut.fi
*/

/*
   The trie is represented by an array and each node consists of an
   unsigned word. The first 5 bits (31-27) indicate the logarithm
   of the branching factor. The next 5 bits (26-22) indicate the
   skip value. The final 22 (21-0) bits is an adress, either to
   another internal node, or the base vector.
   The maximum capacity is 2^21 strings (or a few more). The trie
   is prefixfree. All strings that are prefixes of another string
   are stored separately.
*/

#ifndef SFRT_TRIE_H
#define SFRT_TRIE_H

#define ADRSIZE 32        /* the number of bits in an address */

/* A 32-bit word is used to hold the bit patterns of
   the addresses. In IPv6 this should be 128 bits.
   The following typedef is machine dependent.
   A word must be 32 bits long! */
typedef unsigned long word;

/* The trie is represented by an array and each node in
   the trie is compactly represented using only 32 bits:
   5 + 5 + 22 = branch + skip + adr */
typedef word node_t;

#define NOPRE -1          /* an empty prefix pointer */

#define SETBRANCH(branch)   ((branch)<<27)
#define GETBRANCH(node)     ((node)>>27)
#define SETSKIP(skip)       ((skip)<<22)
#define GETSKIP(node)       ((node)>>22 & 037)
#define SETADR(adr)         (adr)
#define GETADR(node)        ((node) & 017777777)

/* extract n bits from str starting at position p */
#define EXTRACT(p, n, str) ((str)<<(p)>>(32-(n)))

/* remove the first p bits from string */
#define REMOVE(p, str)   ((str)<<(p)>>(p))

/* A next-hop table entry is a 32 bit string */

typedef word policy_t;

/* The routing table entries are initially stored in
   a simple array */

typedef struct entryrec* entry_t;
struct entryrec
{
    word data;         /* the routing entry */
    int len;           /* and its length */
    policy_t policy; /* the corresponding next-hop */
    int pre;           /* this auxiliary variable is used in the */
};                     /* construction of the final data structure */

/* base vector */

typedef struct baserec* base_t;
struct baserec
{
    word str;   /* the routing entry */
    int len;    /* and its length */
    int pre;    /* pointer to prefix table, -1 if no prefix */
    int policy; /* pointer to next-hop table */
};

typedef struct   /* compact version of above */
{ word str;
  int len;
  int pre;
  int policy; } comp_base_t;

/* prefix vector */

typedef struct prerec* pre_t;
struct prerec
{
    int len;    /* the length of the prefix */
    int pre;    /* pointer to prefix, -1 if no prefix */
    int policy; /* pointer to policy table */
};

typedef struct   /* compact version of above */
{ int len;
  int pre;
  int policy; } comp_pre_t;

/* The complete routing table data structure consists of
   a trie, a base vector, a prefix vector, and a next-hop table. */

typedef struct routtablerec* routtable_t;
struct routtablerec
{
    node_t* trie;        /* the main trie search structure */
    int triesize;
    comp_base_t* base;   /* the base vector */
    int basesize;
    comp_pre_t* pre;     /* the prefix vector */
    int presize;
    policy_t* policy;    /* the next-hop table */
    int policysize;

    int dirty;           /* Whether or not the table needs to be rebuilt */
};

#endif

