//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
**  @file        sp_asn1_detect.c
**
**  @author      Daniel Roelker <droelker@sourcefire.com>
**
**  @brief       Decode and detect ASN.1 types, lengths, and data.
**
**  This detection plugin adds ASN.1 detection functions on a per rule
**  basis.  ASN.1 detection plugins can be added by editing this file and
**  providing an interface in the configuration code.
**
**  Detection Plugin Interface:
**
**  asn1: [detection function],[arguments],[offset type],[size]
**
**  Detection Functions:
**
**  bitstring_overflow: no arguments
**  double_overflow:    no arguments
**  oversize_length:    max size (if no max size, then just return value)
**
**  alert udp any any -> any 161 (msg:"foo"; \
**      asn1: oversize_length 10000, absolute_offset 0;)
**
**  alert tcp any any -> any 162 (msg:"foo2"; \
**      asn1: bitstring_overflow, oversize_length 500, relative_offset 7;)
**
**
**  Note that further general information about ASN.1 can be found in
**  the file doc/README.asn1.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "asn1_detect.h"

#include "utils/snort_bounds.h"

#include "asn1_util.h"

/*
**  NAME
**    BitStringOverflow::
*/
/**
**  The necessary info to detect possible bitstring overflows.  Thanks
**  once again to microsoft for keeping us in business.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int BitStringOverflow(ASN1_TYPE* asn1, void*)
{
    if (!asn1)
        return 0;

    /*
    **  Here's what this means:
    **
    **  If the ASN.1 type is a non-constructed bitstring (meaning that
    **  there is only one encoding, not multiple encodings).  And
    **  the number of bits to ignore (this is taken from the first byte)
    **  is greater than the total number of bits, then we have an
    **  exploit attempt.
    */
    if (asn1->ident.tag == SF_ASN1_TAG_BIT_STR && !asn1->ident.flag)
    {
        if (asn1->len.size && asn1->data &&
            (((asn1->len.size - 1)<<3) < (unsigned int)asn1->data[0]))
        {
            return 1;
        }
    }

    return 0;
}

/*
**  NAME
**    DetectBitStringOverflow::
*/
/**
**  This is just a wrapper to the traverse function.  It's important because
**  this allows us to do more with individual nodes in the future.
**
**  @return integer
**
**  @retval 0 failed
**  @rteval 1 detected
*/
static int DetectBitStringOverflow(ASN1_TYPE* asn1)
{
    return asn1_traverse(asn1, nullptr, BitStringOverflow);
}

/*
**  NAME
**    DoubleOverflow::
*/
/**
**  This is the info to detect double overflows.  This may not be a
**  remotely exploitable (remote services may not call the vulnerable
**  microsoft function), but better safe than sorry.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int DoubleOverflow(ASN1_TYPE* asn1, void*)
{
    if (!asn1)
        return 0;

    /*
    **  Here's what this does.
    **
    **  There is a vulnerability in the MSASN1 library when decoding
    **  a double (real) type.  If the encoding is ASCII (specified by
    **  not setting bit 7 or 8), and the buffer is greater than 256,
    **  then you overflow the array in the function.
    */
    if (asn1->ident.tag == SF_ASN1_TAG_REAL && !asn1->ident.flag)
    {
        if (asn1->len.size && asn1->data &&
            ((asn1->data[0] & 0xc0) == 0x00) &&
            (asn1->len.size > 256))
        {
            return 1;
        }
    }

    return 0;
}

/*
**  NAME
**    DetectDoubleOverflow::
*/
/**
**  This is just a wrapper to the traverse function.  It's important because
**  this allows us to do more with individual nodes in the future.
**
**  @return integer
**
**  @retval 0 failed
**  @rteval 1 detected
*/
static int DetectDoubleOverflow(ASN1_TYPE* asn1)
{
    return asn1_traverse(asn1, nullptr, DoubleOverflow);
}

/*
**  NAME
**    OversizeLength::
*/
/**
**  This is the most generic of our ASN.1 detection functionalities.  This
**  will compare the ASN.1 type lengths against the user defined max
**  length and alert if the length is greater than the user supplied length.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int OversizeLength(ASN1_TYPE* asn1, void* user)
{
    unsigned int* max_size;

    if (!asn1 || !user)
        return 0;

    max_size = (unsigned int*)user;

    if (*max_size && *max_size <= asn1->len.size)
        return 1;

    return 0;
}

/*
**  NAME
**    DetectOversizeLength::
*/
/**
**  This is just a wrapper to the traverse function.  It's important because
**  this allows us to do more with individual nodes in the future.
**
**  @return integer
**
**  @retval 0 failed
**  @rteval 1 detected
*/
static int DetectOversizeLength(ASN1_TYPE* asn1, unsigned int max_size)
{
    return asn1_traverse(asn1, (void*)&max_size, OversizeLength);
}

/*
**  NAME
**    Asn1DetectFuncs::
*/
/**
**  The main function for adding ASN.1 detection type functionality.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
static int Asn1DetectFuncs(ASN1_TYPE* asn1, ASN1_CTXT* ctxt, int dec_ret_val)
{
    int iRet = 0;

    /*
    **  Print first, before we do other detection.  If print is the only
    **  option, then we want to evaluate this option as true and continue.
    **  Otherwise, if another option is wrong, then we
    */
    if (ctxt->print)
    {
        asn1_traverse(asn1, nullptr, asn1_print_types);
        iRet = 1;
    }

    /*
    **  Let's check the bitstring overflow.
    */
    if (ctxt->bs_overflow)
    {
        iRet = DetectBitStringOverflow(asn1);
        if (iRet)
            return 1;
    }

    if (ctxt->double_overflow)
    {
        iRet = DetectDoubleOverflow(asn1);
        if (iRet)
            return 1;
    }

    if (ctxt->length)
    {
        iRet = DetectOversizeLength(asn1, ctxt->max_length);

        /*
        **  If we didn't detect any oversize length in the decoded structs,
        **  that might be because we had a really overlong length that is
        **  bigger than our data type could hold.  In this case, it's
        **  overlong too.
        */
        if (!iRet && dec_ret_val == ASN1_ERR_OVERLONG_LEN)
            iRet = 1;

        /*
        **  We add this return in here, so that we follow suit with the
        **  previous detections.  Just trying to short-circuit any future
        **  problems if we change the code flow here.
        */
        if (iRet)
            return 1;
    }

    return iRet;
}

/*
**  NAME
**    Asn1DoDetect::
*/
/**
**  Workhorse detection function.  Does not depend on OTN.
**  We check all the offsets to make sure we're in bounds, etc.
**
**  @return integer
**
**  @retval 0 failed
**  @retval 1 detected
*/
int Asn1DoDetect(const uint8_t* data, uint16_t dsize, ASN1_CTXT* ctxt, const uint8_t* rel_ptr)
{
    ASN1_TYPE* asn1;
    int iRet;
    unsigned int size;
    const uint8_t* start;
    const uint8_t* end;
    const uint8_t* offset = nullptr;

    /*
    **  Failed if there is no data to decode.
    */
    if (data == nullptr)
        return 0;

    start = data;
    end = start + dsize;

    switch (ctxt->offset_type)
    {
    case REL_OFFSET:
        if (!rel_ptr)
            return 0;

        /*
        **  Check that it is in bounds first.
        **  Because rel_ptr can be "end" in the last match,
        **  use end + 1 for upper bound
        **  Bound checked also after offset is applied
        */
        if (!inBounds(start, end + 1, rel_ptr))
            return 0;

        offset = rel_ptr+ctxt->offset;

        if (!inBounds(start, end, offset))
            return 0;

        break;

    case ABS_OFFSET:
    default:
        offset = start+ctxt->offset;

        if (!inBounds(start, end, offset))
            return 0;

        break;
    }

    /*
    **  Set size for asn1_decode().  This should never be <0 since
    **  we do the previous in bounds check.
    */
    size = end - offset;

    iRet = asn1_decode(offset, size, &asn1);
    if (iRet && !asn1)
        return 0;

    /*
    **  Let's do detection now.
    */
    return Asn1DetectFuncs(asn1, ctxt, iRet);
}

