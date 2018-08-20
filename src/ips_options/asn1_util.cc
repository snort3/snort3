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

/**
**  @file       asn1.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      ASN.1 Decoding API for BER and DER encodings.
**
**  Author: Daniel Roelker
**
**  ASN.1 decoding functions that incorporate an internal stack for
**  processing.  That way we don't have to worry about attackers trying
**  to overload the machine stack.
**
**  Handles both DER and BER encodings, and also the indefinite encoding
**  that BER supports.  Lots of functionality can be added on top of
**  this library.  SNMP will probably be the first.
**
**  NOTES:
**    - Stop using global variables so we can have multiple instances,
**      but we don't need that functionality right now.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "asn1_util.h"

#include "main/snort_config.h"
#include "utils/util.h"

/*
**  Macros
*/
#define SF_ASN1_CLASS(c)   (((uint8_t)(c)) & SF_ASN1_CLASS_MASK)
#define SF_ASN1_FLAG(c)    (((uint8_t)(c)) & SF_ASN1_FLAG_MASK)
#define SF_ASN1_TAG(c)     (((uint8_t)(c)) & SF_ASN1_TAG_MASK)
#define SF_ASN1_LEN_EXT(c) (((uint8_t)(c)) & SF_BER_LEN_MASK)

#define ASN1_OOB(s,e,d)      (!(((s) <= (d)) && ((d) < (e))))
#define ASN1_FATAL_ERR(e)    ((e) < 0)
#define ASN1_NONFATAL_ERR(e) ((e) > 0)

#define ASN1_MAX_STACK 128

static ASN1_CONFIG asn1_config;
static THREAD_LOCAL int node_index;

/*
**  NAME
**    asn1_init_node_index::
*/
/**
**  This function should get called whenever we decode a new ASN.1
**  string to initialize the memory.
**
**  @return void
*/
static void asn1_init_node_index()
{
    node_index = 0;
}

/*
**  NAME
**    asn1_node_alloc::
*/
/**
**  Allocate an ASN1_NODE.
**
**  @return ASN1_TYPE *
**
**  @retval NULL memory allocation failed
**  @retval !NULL function successful
*/
static ASN1_TYPE* asn1_node_alloc()
{
    if ((asn1_config.mem == nullptr) || (asn1_config.num_nodes <= node_index))
        return nullptr;

    return &asn1_config.mem[node_index++];
}

/*
**  NAME
**    asn1_init_mem::
*/
/**
**  This function initializes the number of nodes that we want to track in
**  an ASN.1 decode.  Pass in the max number of nodes for an ASN.1 decode and
**  we will track that many.
**
**  @return integer
**
**  @retval ASN1_OK function successful
**  @retval ASN1_ERR_MEM_ALLOC memory allocation failed
**  @retval ASN1_ERR_INVALID_ARG invalid argument
*/
void asn1_init_mem(snort::SnortConfig* sc)
{
    int num_nodes;

    if (sc->asn1_mem != 0)
        num_nodes = sc->asn1_mem;
    else
        num_nodes = 256;

    if (num_nodes <= 0)
        return;

    asn1_config.mem = (ASN1_TYPE*)snort_calloc(num_nodes, sizeof(ASN1_TYPE));
    asn1_config.num_nodes = num_nodes;
    node_index = 0;
}

/*
**  NAME
**    asn1_free_mem::
*/
/**
**  This function frees the number of nodes that we were tracking in
**  an ASN.1 decode.
**
**  @return none
**
*/
void asn1_free_mem(snort::SnortConfig*)
{
    if (asn1_config.mem != nullptr)
    {
        snort_free(asn1_config.mem);
        asn1_config.mem = nullptr;
    }
}

/*
**  NAME
**    asn1_decode_tag_num_ext::
*/
/**
**  This routine decodes extended tag numbers and checks for overlong
**  tag numbers, etc.
**
**  @param ASN1_DATA ptr to data
**  @param u_int ptr to tag num
**
**  @return integer
**
**  @retval ASN1_OK function successful
**  @retval ASN1_ERR_OVERLONG_LEN tag number too large
**  @retval ASN1_ERR_OOB encoding goes out of bounds
**  @retval ASN1_ERR_NULL_MEM function arguments are NULL
*/
static int asn1_decode_tag_num_ext(ASN1_DATA* asn1_data, u_int* tag_num)
{
    int iExtension = 0;
    u_int new_tag_num;

    if (!asn1_data || !tag_num)
        return ASN1_ERR_NULL_MEM;

    *tag_num = 0;

    /*
    **  Loop through the tag type while extension bit is set
    */
    do
    {
        /*
        **  Is this an extension byte?
        */
        iExtension = SF_ASN1_LEN_EXT(*asn1_data->data);

        new_tag_num = ((*tag_num << 7) | (*asn1_data->data & 0x7f));
        if (*tag_num != 0 && new_tag_num <= *tag_num)
        {
            return ASN1_ERR_OVERLONG_LEN;
        }

        *tag_num = new_tag_num;

        asn1_data->data++;
        if (ASN1_OOB(asn1_data->start, asn1_data->end, asn1_data->data))
        {
            return ASN1_ERR_OOB;
        }
    }
    while (iExtension);

    return ASN1_OK;
}

/*
**  NAME
**    asn1_decode_ident::
*/
/**
**  This function decodes the identifier byte(s) of an ASN.1 structure.
**  We handle long tag numbers and check for overflows in the extended
**  tag numbers.
**
**  @return integer
**
**  @retval ASN1_ERR_NULL_MEM function arguments are NULL
**  @retval ASN1_ERR_OOB buffer out of bounds
**  @retval ASN1_ERR_INVALID_BER_TAG_LEN tag num too large or bad encoding
**  @retval ASN1_OK function ok
*/
static int asn1_decode_ident(ASN1_TYPE* asn1_type, ASN1_DATA* asn1_data)
{
    ASN1_IDENT* ident;

    if (!asn1_type || !asn1_data)
        return ASN1_ERR_NULL_MEM;

    ident = &asn1_type->ident;

    ident->asn1_class = SF_ASN1_CLASS(*asn1_data->data);
    ident->flag  = SF_ASN1_FLAG(*asn1_data->data);
    ident->tag   = SF_ASN1_TAG(*asn1_data->data);

    asn1_data->data++;
    if (ASN1_OOB(asn1_data->start, asn1_data->end, asn1_data->data))
    {
        //printf("** decode_ident:  oob\n");
        return ASN1_ERR_OOB;
    }

    /*
    **  Is tag extended?
    */
    if (ident->tag == SF_ASN1_TAG_EXTENSION)
    {
        ident->tag_type = SF_ASN1_TAG_EXTENSION;

        if ( asn1_decode_tag_num_ext(asn1_data, &ident->tag) )
        {
            //printf("** decode_ident: ext_len error\n");
            return ASN1_ERR_INVALID_BER_TAG_LEN;
        }
    }

    return ASN1_OK;
}

/*
**  NAME
**    asn1_decode_len_type::
*/
/**
**  Determine the type of len encoding.  Could be short, long or
**  indeterminate.
**
**  @return integer
**
**  @retval SF_BER_LEN_DEF_LONG extended length
**  @retval SF_BER_LEN_DEF_SHORT one byte length < 127
**  @retval SF_BER_LEN_INDEF indeterminate length
*/
static int asn1_decode_len_type(const uint8_t* data)
{
    int iExt;

    iExt = SF_ASN1_LEN_EXT(*data);
    if (iExt)
    {
        if (*data & 0x7f)
        {
            return SF_BER_LEN_DEF_LONG;
        }
        else
        {
            return SF_BER_LEN_INDEF;
        }
    }

    return SF_BER_LEN_DEF_SHORT;
}

/*
**  NAME
**    asn1_decode_len_ext::
*/
/**
**  Decode the extended length version.  Basically we read the first
**  byte for the number of bytes in the extended length.  We then read
**  that number of bytes to determine the length.  If the number of bytes
**  in the length is greater than our variable, then we return
**  ASN1_ERR_OVERLONG_LEN, and exit decoding.
**
**  @return integer
**
**  @retval ASN1_ERR_NULL_MEM function arguments NULL
**  @retval ASN1_ERR_OVERLONG_LEN length to long for us to decode
**  @retval ASN1_ERR_OOB out of bounds condition
**  @retval ASN1_OK function successful
*/
static int asn1_decode_len_ext(ASN1_DATA* asn1_data, u_int* size)
{
    int iBytes;
    int iCtr;
    u_int new_size;

    if (!asn1_data || !size)
        return ASN1_ERR_NULL_MEM;

    *size = 0;

    iBytes = (*asn1_data->data & 0x7f);

    asn1_data->data++;
    if (ASN1_OOB(asn1_data->start, asn1_data->end, asn1_data->data))
    {
        return ASN1_ERR_OOB;
    }

    for (iCtr = 0; iCtr < iBytes; iCtr++)
    {
        new_size = ((*size << 8) | (*asn1_data->data));

        /*
        **  If we've just added some data to the size, and
        **  we are still the same or less than the previous
        **  size, we've just overflowed our variable
        */
        if (*size != 0 && new_size <= *size)
        {
            return ASN1_ERR_OVERLONG_LEN;
        }

        *size = new_size;

        asn1_data->data++;
        if (ASN1_OOB(asn1_data->start, asn1_data->end, asn1_data->data))
        {
            /*
            **  Check to see if this was just an extended length that was zero at
            **  the end of the buffer.  If it was, then return normal.
            */
            if (*size == 0 && (iCtr+1) == iBytes)
                break;

            return ASN1_ERR_OOB;
        }
    }

    return ASN1_OK;
}

/*
**  NAME
**    asn1_decode_len::
*/
/**
**  This function decodes the ASN.1 type length.  Determines what type of
**  BER encoding is used for the length and decodes that length.
**
**  @return integer
**
**  @retval ASN1_ERR_NULL_MEM function arguments NULL
**  @retval ASN1_ERR_FATAL should never get this
**  @retval ASN1_ERR_OOB out of bounds condition
**  @retval ASN1_OK function successful
*/
static int asn1_decode_len(ASN1_TYPE* asn1_type, ASN1_DATA* asn1_data)
{
    ASN1_LEN* len;
    int iRet;

    if (!asn1_type || !asn1_data)
        return ASN1_ERR_NULL_MEM;

    len = &asn1_type->len;

    len->type = (unsigned char)asn1_decode_len_type(asn1_data->data);

    switch (len->type)
    {
    case SF_BER_LEN_DEF_SHORT:
        len->size = *asn1_data->data;

        (asn1_data->data)++;
        if (ASN1_OOB(asn1_data->start, asn1_data->end, asn1_data->data))
        {
            /*
            **  Only return OOB if the short length wasn't zero.  Otherwise,
            **  it's a valid encoding.
            */
            if (len->size != 0)
                return ASN1_ERR_OOB;
        }

        break;

    case SF_BER_LEN_DEF_LONG:
        iRet = asn1_decode_len_ext(asn1_data, &len->size);
        if (iRet)
            return iRet;

        break;

    case SF_BER_LEN_INDEF:
        /*
        **  Not sure what to do here, so we'll just set the length
        **  to 0 and proceed for now.
        */
        len->size = 0;

        asn1_data->data++;
        if (ASN1_OOB(asn1_data->start, asn1_data->end, asn1_data->data))
            return ASN1_ERR_OOB;

        break;

    default:
        /*
        **  This should be one of the three values.  So we are in
        **  error condition.
        */
        return ASN1_ERR_FATAL;
    }

    return ASN1_OK;
}

/*
**  NAME
**    asn1_is_eoc::
*/
/**
**  This function checks and ASN1_TYPE for end-of-content encoding.  This
**  doesn't determine that this is what it is, but what it could be.
**
**  @return int
**
**  @retval 0 not EOC
**  @retval 1 is EOC
*/
static int asn1_is_eoc(ASN1_TYPE* asn1)
{
    if (!asn1)
        return 0;

    if (asn1->ident.asn1_class == 0x00 && asn1->ident.flag == 0x00 &&
        asn1->ident.tag == 0x00 && asn1->len.type == SF_BER_LEN_DEF_SHORT &&
        asn1->len.size == 0)
    {
        return 1;
    }

    return 0;
}

/*
**  NAME
**    asn1_decode_type::
*/
/**
**  This function decodes an ASN1_TYPE structure.  It processes the type in
**  three parts.
**
**  1) Identifier
**  2) Length
**  3) Data
**
**  The data processing skips over primitive data (if it can) and processes
**  construct data (if it can).
**
**  This function also updates the data and len ptrs so we continue moving
**  through the data.
**
**  @return integer
**
**  @retval ASN1_OK function successful
**  @retval ASN1_ERR_MEM_ALLOC memory allocation failed
**  @retval ASN1_ERR_INVALID_INDEF_LEN invalid indefinite encoding
**  @retval ASN1_ERR_INVALID_ARG invalid argument
**  @retval ASN1_ERR_OOB out of bounds
*/
static int asn1_decode_type(const uint8_t** data, u_int* len, ASN1_TYPE** asn1_type)
{
    ASN1_DATA asn1data;
    u_int uiRawLen;
    int iRet;

    if (!*data)
        return ASN1_ERR_INVALID_ARG;

    *asn1_type = nullptr;

    /*
    **  Check len first, because if it's 0, then we already decoded a valid
    **  construct.  We let the caller know this, by returning OK, but setting
    **  the asn1_type ptr to NULL.
    */
    if (*len == 0)
        return ASN1_OK;

    if (ASN1_OOB(*data, (*data) + *len, *data))
        return ASN1_ERR_OOB;

    *asn1_type = asn1_node_alloc();
    if (*asn1_type == nullptr)
    {
        return ASN1_ERR_MEM_ALLOC;
    }
    memset(*asn1_type, 0x00, sizeof(ASN1_TYPE));

    asn1data.start = *data;
    asn1data.end   = (*data) + *len;
    asn1data.data  = *data;

    iRet = asn1_decode_ident(*asn1_type, &asn1data);
    if (iRet)
    {
        return iRet;
    }

    iRet = asn1_decode_len(*asn1_type, &asn1data);
    if (iRet)
    {
        return iRet;
    }

    /*
    **  Set this variable here, so we can set the data_len for
    **  indeterminate constructs.
    */
    uiRawLen = asn1data.end - asn1data.data;

    /*
    **  This is an important check.  If the length is zero, it means that
    **  we've either hit a zero length type or we've hit a BER indefinite
    **  encoding (hate those).
    **
    **  Standard says that only constructs can have the indefinite length
    **  encoding, but we still need to "prove" that.  Thanks M$.
    */
    if (!(*asn1_type)->len.size)
    {
        if ((*asn1_type)->len.type != SF_BER_LEN_INDEF ||
            (*asn1_type)->ident.flag == SF_ASN1_FLAG_CONSTRUCT)
        {
            (*asn1_type)->data = asn1data.data;

            if ((*asn1_type)->len.type == SF_BER_LEN_INDEF)
            {
                (*asn1_type)->data_len = uiRawLen;
            }
            else
            {
                /*
                **  If we're not an indefinite type, then we check to
                **  see if we are an eoc, so we don't have to check again.
                */
                (*asn1_type)->data_len = 0;

                if (asn1_is_eoc(*asn1_type))
                    (*asn1_type)->eoc = 1;
            }

            goto valid;
        }

        return ASN1_ERR_INVALID_INDEF_LEN;
    }

    /*
    **  Set data ptr for asn1 types that have data.
    */
    (*asn1_type)->data = asn1data.data;

    /*
    **  Check for the ASN.1 type being larger than we have room for.
    */
    if (uiRawLen < (*asn1_type)->len.size)
    {
        (*asn1_type)->data_len = uiRawLen;

        /*
        **  If we're a construct, then don't skip over the data because
        **  we have to process it.
        */
        if ((*asn1_type)->ident.flag == SF_ASN1_FLAG_CONSTRUCT)
            goto valid;

        return ASN1_ERR_OOB;
    }

    /*
    **  We got enough data in the buffer for the true identifier size, so
    **  we set it.
    */
    (*asn1_type)->data_len = (*asn1_type)->len.size;

    /*
    **  Only jump data that's not going to be decoded.  That means jump
    **  over primitive data and decode construct data.
    */
    if (!((*asn1_type)->ident.flag == SF_ASN1_FLAG_CONSTRUCT))
    {
        asn1data.data += (*asn1_type)->len.size;
    }

valid:
    /*
    **  Update data buffer, before we return.  Depending on if we just decoded
    **  a zero length identifier and are on the last data byte, we could be at
    **  the end of our buffer.  Otherwise, we're still in the buffer.
    */
    *len  = asn1data.end - asn1data.data;
    *data = asn1data.data;

    return ASN1_OK;
}

/*
**  NAME
**    asn1_decode::
*/
/**
**  This function decodes an ASN.1 string and returns the decoded
**  structures.  We BER encoding, which means we handle both
**  definite and indefinite length encodings (that was a B).
**
**  @return integer
**
**  @retval  ASN1_OK function successful
**  @retval !ASN1_OK lots of error conditions, figure it out
*/
int asn1_decode(const uint8_t* data, u_int len, ASN1_TYPE** asn1_type)
{
    ASN1_TYPE* cur;
    ASN1_TYPE* child = nullptr;
    ASN1_TYPE* indef;
    ASN1_TYPE* asnstack[ASN1_MAX_STACK];

    const uint8_t* end;
    u_int con_len;
    int index = 0;
    int iRet;

    if (!data || !len)
        return ASN1_ERR_NULL_MEM;

    asn1_init_node_index();

    /*
    **  Keep track of where the end of the data buffer is so we can continue
    **  processing if there is a construct.
    */
    end = data + len;

    iRet = asn1_decode_type(&data,&len,asn1_type);
    if (iRet || !(*asn1_type))
    {
        //printf("** initial bad decode\n");
        return iRet;
    }

    cur  = *asn1_type;

    while (cur)
    {
        /*
        **  This is where we decode the ASN.1 constructs.  We do while()
        **  because we may have back to back constructs.  We bail on the
        **  first identifier that isn't a construct.
        */
        while (cur && cur->ident.flag == SF_ASN1_FLAG_CONSTRUCT)
        {
            if (index < ASN1_MAX_STACK)
                asnstack[index++] = cur;
            else
                return ASN1_ERR_STACK;

            /*
            **  We now set the current len for this constructs true length,
            **  or raw length if true length is past buffer.
            */
            if (cur->len.type != SF_BER_LEN_INDEF)
            {
                if (len < cur->data_len)
                    return ASN1_ERR_OVERLONG_LEN;

                len = cur->data_len;
            }

            iRet = asn1_decode_type(&data, &len, &cur->cnext);
            if (iRet)
            {
                return iRet;
            }

            /*
            **  Check next child for ending of indefinite encodings.
            */
            if (cur->cnext && cur->cnext->eoc)
            {
                if (index && (indef = asnstack[--index]) != nullptr)
                {
                    if (indef->len.type == SF_BER_LEN_INDEF)
                    {
                        indef->len.size = data - indef->data - 2;
                        indef->data_len = indef->len.size;

                        cur->cnext = nullptr;
                        cur = indef;
                        break;
                    }
                    else
                    {
                        /*
                        **  Not an EOC type, so it's just a strange child
                        **  encoding.  Put the construct back on the stack.
                        */
                        asnstack[index++] = indef;
                    }
                }
            }

            cur = cur->cnext;
        }

        /*
        **  If there is a node, then process any peers that this node has.
        */
        if (cur)
        {
            iRet = asn1_decode_type(&data, &len, &cur->next);
            if (iRet)
                return iRet;

            /*
            **  Cycle through any eoc that might be back to back
            */
            while (cur->next && cur->next->eoc)
            {
                if (index && (indef = asnstack[--index]) != nullptr)
                {
                    if (indef->len.type == SF_BER_LEN_INDEF)
                    {
                        indef->len.size = data - indef->data - 2;
                        indef->data_len = indef->len.size;
                        cur->next = nullptr;
                        cur = indef;

                        iRet = asn1_decode_type(&data, &len, &cur->next);
                        if (iRet)
                        {
                            return iRet;
                        }

                        continue;
                    }

                    asnstack[index++] = indef;
                }

                break;
            }

            cur = cur->next;
            if (cur)
                continue;
        }

        /*
        **  We only get here if the peer decode fails.
        **
        **  Traverse the stack and close off any constructs that we
        **  are done with.  This gets a little trickier, because we have to
        **  check for additional peers for each construct, depending on the
        **  length of the parent construct.
        */
        while (index && (cur = asnstack[--index]) != nullptr)
        {
            /*
            **  Get the construct length and set the length appropriately
            **  if there is more data in this construct.
            */
            con_len = data - cur->data;
            if (cur->data_len > con_len)
            {
                len = cur->data_len - con_len;
            }

            /*
            **  If this construct has no more data left, then save it off as
            **  the last child of the previous construct.
            */
            if (len == 0)
            {
                child = cur;
            }
            else if (child)
            {
                /*
                **  Means this construct has more data left, so if the child is set
                **  then we set it's next ptr.  Otherwise, this means we are in
                **  an indeterminate construct, and need to check for eoc before we
                **  continue processing.
                */
                asnstack[index++] = cur;
                cur   = child;
                child = nullptr;
            }

            iRet = asn1_decode_type(&data, &len, &cur->next);
            if (iRet)
            {
                return iRet;
            }

            if (cur->next && cur->next->eoc)
            {
                if (index && (indef = asnstack[--index]) != nullptr)
                {
                    if (indef->len.type == SF_BER_LEN_INDEF)
                    {
                        indef->len.size = data - indef->data - 2;
                        indef->data_len = indef->len.size;
                        cur->next = nullptr;
                        cur = indef;
                    }
                    else
                    {
                        asnstack[index++] = indef;
                    }
                }
            }

            /*
            **  This logic tell us that we are on the root construct, but there
            **  are additional peers because there is more data.  We recalculate
            **  the length and continue on.
            **
            **  NOTE:
            **    We may not want this because research may only be able to point
            **    us at the first sequence and it's anyone's guess after that.
            */
            if (!index && !(cur->next) && (data < end))
            {
                len = (end - data);

                iRet = asn1_decode_type(&data, &len, &cur->next);
                if (iRet)
                    return iRet;
            }

            cur = cur->next;
            if (cur)
                break;
        }

        /*
        **  The loop logic bails us out if there is no cur.
        */
    }

    return ASN1_OK;
}

/*
**  NAME
**    asn1_traverse::
*/
/**
**  This function traverses a decoded ASN1 structure, applying a detection
**  function for the different types.  This is just to make this user stack
**  generic AND easy.
**
**  @return integer
**
**  @retval 1 detection function successful
**  @retval 0 detection function unsuccessful
*/
int asn1_traverse(ASN1_TYPE* asn1, void* user,
    int (* DetectFunc)(ASN1_TYPE*, void*))
{
    ASN1_TYPE* asnstack[ASN1_MAX_STACK];
    int index = 0;
    ASN1_TYPE* cur;
    int iRet;

    if (!asn1)
        return 0;

    cur = asn1;

    while (cur)
    {
        while (cur && cur->ident.flag == SF_ASN1_FLAG_CONSTRUCT)
        {
            if (index < ASN1_MAX_STACK)
                asnstack[index++] = cur;
            else
                return 0;

            iRet = DetectFunc(cur, user);
            if (iRet)
                return 1;

            cur = cur->cnext;
        }

        if (cur)
        {
            iRet = DetectFunc(cur, user);
            if (iRet)
                return 1;

            cur = cur->next;
            if (cur)
                continue;
        }

        while (index && (cur = asnstack[--index]) != nullptr)
        {
            cur = cur->next;
            if (cur)
                break;
        }
    }

    return 0;
}

/*
**  NAME
**    asn1_print_types::
*/
/**
**  Print out the ASN.1 type.
**
**  @return integer
**
**  @retval 0 printed
*/
int asn1_print_types(ASN1_TYPE* asn1_type, void* user)
{
    unsigned int iTabs = 0;
    unsigned int iCtr;

    if (user)
        iTabs = *((int*)user);

    for (iCtr = 0; iCtr < iTabs; iCtr++)
        printf("    ");

    printf("## PRINT ASN1_TYPE STRUCTURE ##\n");

    for (iCtr = 0; iCtr < iTabs; iCtr++)
        printf("    ");

    printf("IDENT - asn1_class: %.2x | flag: %.2x | tag_type: %.2x | "
        "tag_num: %u\n", asn1_type->ident.asn1_class, asn1_type->ident.flag,
        asn1_type->ident.tag_type, asn1_type->ident.tag);

    for (iCtr = 0; iCtr < iTabs; iCtr++)
        printf("    ");

    printf("LEN - type: %d | size: %u\n", asn1_type->len.type,
        asn1_type->len.size);

    for (iCtr = 0; iCtr < iTabs; iCtr++)
        printf("    ");

    printf("DATA | data_len: %u | ", asn1_type->data_len);
    if (asn1_type->data)
    {
        for (iCtr = 0; iCtr < asn1_type->data_len; iCtr++)
            printf(" %.2x", asn1_type->data[iCtr]);
    }
    else
    {
        printf(" NULL");
    }

    printf("\n\n");

    /*

    printf("\n");
    //if(BitStringOverflow(asn1_type))
    //{
    //    printf("BITSTRING OVERFLOW\n");
    //}
    printf("\n");

    if(asn1_type->cnext)
        asn1_print_types(asn1_type->cnext, iTabs+1);

    if(asn1_type->next)
        asn1_print_types(asn1_type->next, iTabs);
    */

    return 0;
}

#ifdef I_WANT_MAIN_DAMMIT
static int BitStringOverflow(ASN1_TYPE* asn1_type)
{
    if (!asn1_type)
        return 0;

    if (asn1_type->ident.tag == SF_ASN1_TAG_BIT_STR && !asn1_type->ident.flag)
    {
        if (((asn1_type->len.size - 1)*8) < (u_int)asn1_type->data[0])
        {
            return 1;
        }
    }

    return 0;
}

/*
**  Program reads from stdin and decodes the hexadecimal ASN.1 stream
**  into identifier,len,data.
*/
int main(int argc, char** argv)
{
    ASN1_TYPE* asn1_type;
    char line[10000];
    u_int ctmp;
    char* buf;
    int buf_size;
    int iCtr;
    int iRet;

    fgets(line, sizeof(line), stdin);
    buf_size = strlen(line);

    while (buf_size && line[buf_size-1] <= 0x20)
    {
        buf_size--;
        line[buf_size] = 0x00;
    }

    if (!buf_size)
    {
        printf("** No valid characters in data string.\n");
        return 1;
    }

    if (buf_size % 2)
    {
        printf("** Data must be represent in hex, meaning that there is an "
            "odd number of characters in the data string.\n");
        return 1;
    }

    buf_size >>= 1;

    buf = snort_calloc(buf_size + 1);

    for (iCtr = 0; iCtr < buf_size; iCtr++)
    {
        if (!(isxdigit(line[iCtr*2]) && isxdigit(line[(iCtr*2)+1])))
        {
            printf("** Data stream is not all hex digits.\n");
            return 1;
        }

        sscanf(&line[iCtr*2], "%2x", &ctmp);
        buf[iCtr] = (char)ctmp;
    }

    buf[iCtr] = 0x00;

    asn1_init_mem(256);

    iRet = asn1_decode(buf, buf_size, &asn1_type);
    if (iRet && !asn1_type)
    {
        printf("** FAILED\n");
        return 1;
    }

    printf("** iRet = %d\n", iRet);

    asn1_print_types(asn1_type, 0);

    snort_free(buf);

    return 0;
}

#endif

