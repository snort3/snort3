//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

#ifndef ASN1_H
#define ASN1_H

/*
**  ASN.1 Identifier Classes
*/
#define SF_ASN1_CLASS_MASK        0xc0
#define SF_ASN1_CLASS_UNIVERSAL   0x00
#define SF_ASN1_CLASS_APPLICATION 0x40
#define SF_ASN1_CLASS_CONTEXT     0x80
#define SF_ASN1_CLASS_PRIVATE     0xc0

/*
**  ASN.1 Identifier Flags
*/
#define SF_ASN1_FLAG_MASK       0x20
#define SF_ASN1_FLAG_PRIMITIVE  0x00
#define SF_ASN1_FLAG_CONSTRUCT  0x20

/*
**  ASN.1 Universal Tags
*/
#define SF_ASN1_TAG_MASK      0x1f

#define SF_ASN1_TAG_RSV_ENC   0
#define SF_ASN1_TAG_BOOL      1
#define SF_ASN1_TAG_INT       2
#define SF_ASN1_TAG_BIT_STR   3
#define SF_ASN1_TAG_OCT_STR   4
#define SF_ASN1_TAG_NULL      5
#define SF_ASN1_TAG_OBJ_IDENT 6
#define SF_ASN1_TAG_OBJ_DESC  7
#define SF_ASN1_TAG_EXT       8
#define SF_ASN1_TAG_REAL      9
#define SF_ASN1_TAG_ENUM      10
#define SF_ASN1_TAG_EMB_PDV   11
#define SF_ASN1_TAG_REL_OBJ   13

#define SF_ASN1_TAG_SEQ       16
#define SF_ASN1_TAG_SET       17

#define SF_ASN1_TAG_UTF8_STR  12
#define SF_ASN1_TAG_NUM_STR   18
#define SF_ASN1_TAG_PRINT_STR 19
#define SF_ASN1_TAG_T61_STR   20
#define SF_ASN1_TAG_VID_STR   21
#define SF_ASN1_TAG_IA5_STR   22
#define SF_ASN1_TAG_GRAPH_STR 25
#define SF_ASN1_TAG_VIS_STR   26
#define SF_ASN1_TAG_GEN_STR   27
#define SF_ASN1_TAG_UNIV_STR  28
#define SF_ASN1_TAG_BMP_STR   30

#define SF_ASN1_TAG_UTC_TIME  23
#define SF_ASN1_TAG_GEN_TIME  24

#define SF_ASN1_TAG_EXTENSION 31

/*
**  BER Length Decoding
*/
#define SF_BER_LEN_MASK      0x80
#define SF_BER_LEN_DEF_SHORT 1
#define SF_BER_LEN_DEF_LONG  2
#define SF_BER_LEN_INDEF     3

struct ASN1_LEN
{
    unsigned char type;
    unsigned int size;
};

struct ASN1_IDENT
{
    unsigned char asn1_class;
    unsigned char flag;
    unsigned char tag_type;
    unsigned int tag;
};

struct ASN1_TYPE
{
    ASN1_IDENT ident;
    ASN1_LEN len;

    const unsigned char* data;
    unsigned int data_len;

    unsigned char eoc;

    struct ASN1_TYPE* next;
    struct ASN1_TYPE* cnext;
};

struct ASN1_DATA
{
    const unsigned char* data;
    const unsigned char* start;
    const unsigned char* end;
    unsigned int len;
};

struct ASN1_CONFIG
{
    ASN1_TYPE* mem;
    int num_nodes;
};

namespace snort
{
struct SnortConfig;
}

/*
**  Error Codes
*/
#define ASN1_ERR_OOB          1
#define ASN1_ERR_NONFATAL     2
#define ASN1_ERR_OVERLONG_LEN 3

#define ASN1_OK      0

#define ASN1_ERR_NULL_MEM            (-1)
#define ASN1_ERR_INVALID_BER_TAG_LEN (-3)
#define ASN1_ERR_MEM_ALLOC           (-4)
#define ASN1_ERR_FATAL               (-5)
#define ASN1_ERR_INVALID_INDEF_LEN   (-6)
#define ASN1_ERR_INVALID_ARG         (-7)
#define ASN1_ERR_STACK               (-8)

void asn1_init_mem(snort::SnortConfig*);
void asn1_free_mem(snort::SnortConfig*);
int asn1_decode(const unsigned char* data, unsigned int len, ASN1_TYPE** asn1_type);
int asn1_print_types(ASN1_TYPE* asn1_type, void* user);
int asn1_traverse(ASN1_TYPE* asn1, void* user,
    int (* DetectFunc)(ASN1_TYPE*, void*));

#endif

