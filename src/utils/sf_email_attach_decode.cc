//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>

#include "sf_email_attach_decode.h"

#include "snort_types.h"
#include "util.h"

#define UU_DECODE_CHAR(c) (((c) - 0x20) & 0x3f)

int sf_qpdecode(char *src, uint32_t slen, char *dst, uint32_t dlen, uint32_t *bytes_read, uint32_t *bytes_copied )
{
    char ch;

    if(!src || !slen || !dst || !dlen || !bytes_read || !bytes_copied )
        return -1;

    *bytes_read = 0;
    *bytes_copied = 0;

    while( (*bytes_read < slen) && (*bytes_copied < dlen))
    {
        ch = src[*bytes_read];
        *bytes_read += 1;
        if( ch == '=' )
        {
            if( (*bytes_read < slen))
            {
                if(src[*bytes_read] == '\n')
                {
                    *bytes_read += 1;
                    continue;
                }
                else if( *bytes_read < (slen - 1) )
                {
                    char ch1 = src[*bytes_read];
                    char ch2 = src[*bytes_read + 1];
                    if( ch1 == '\r' && ch2 == '\n')
                    {
                        *bytes_read += 2;
                        continue;
                    }
                    if (isxdigit((int)ch1) && isxdigit((int)ch2))
                    {
                        char hexBuf[3];
                        char *eptr;
                        hexBuf[0] = ch1;
                        hexBuf[1] = ch2;
                        hexBuf[2] = '\0';
                        dst[*bytes_copied]= (char)strtoul(hexBuf, &eptr, 16);
                        if((*eptr != '\0'))
                        {
                            return -1;
                        }
                        *bytes_read += 2;
                        *bytes_copied +=1;
                        continue;
                    }
                    dst[*bytes_copied] = ch;
                    *bytes_copied +=1;
                    continue;
                }
                else
                {
                    *bytes_read -= 1;
                    return 0;
                }
            }
            else
            {
                *bytes_read -= 1;
                return 0;
            }
        }
        else if (isprint(ch) || isblank(ch))
        {
            dst[*bytes_copied] = ch;
            *bytes_copied +=1;
        }
    }

    return 0;

}
int sf_uudecode(uint8_t *src, uint32_t slen, uint8_t *dst, uint32_t dlen, uint32_t *bytes_read, uint32_t *bytes_copied, uint8_t *begin_found, uint8_t *end_found)
{
    uint8_t *sod;
    int sol = 1, length = 0;
    uint8_t *ptr, *end, *dptr, *dend;

    if(!src || !slen || !dst || !dlen ||  !bytes_read || !bytes_copied || !begin_found || !end_found )
        return -1;

    ptr = src;
    end = src + slen;
    dptr = dst;
    dend = dst + dlen;
    /* begin not found. Search for begin */
    if( !(*begin_found) )
    {
        if( slen < 5 )
        {
            /* Not enough data to search */
            *bytes_read = 0;
            *bytes_copied = 0;
            return 0;
        }
        else
        {
            sod = (uint8_t *)SnortStrnStr((const char *)src, 5 , "begin");
            if(sod)
            {
                *begin_found = 1;
                /*begin str found. Move to the actual data*/
                ptr = (uint8_t *)SnortStrnStr((const char *)(sod), (end - sod), "\n");
                if( !ptr )
                {
                    *bytes_read = slen;
                    *bytes_copied = 0;
                    return 0;
                }
            }
            else
            {
                /*Encoded data for UUencode should start with begin. Error encountered.*/
                return -1;
            }
        }
    }

    while( (ptr < end) && (dptr < dend))
    {
        if(*ptr == '\n')
        {
            sol = 1;
            ptr++;
            continue;
        }

        if(sol)
        {
            sol = 0;
            length = UU_DECODE_CHAR(*ptr);

            if( length <= 0 )
            {
                /* empty line with no encoded characters indicates end of output */
                break;
            }
            else if( length == 5 )
            {
                if(*ptr == 'e')
                {
                    *end_found = 1;
                    break;
                }
            }
            /* check if destination buffer is big enough */
            if(( dend - dptr) < length)
            {
                length = dend - dptr;
            }

            length = (length * 4) / 3 ;

            /*check if src buffer has enough encoded data*/
            if( (end - (ptr + 1)) < length)
            {
                /*not enough data to decode. We will wait for the next packet*/
                break;
            }

            ptr++;
            
            while( length > 0 )
            {
                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 2) | (UU_DECODE_CHAR(ptr[1]) >> 4);
                ptr++;
                if(--length == 0 )
                    break;

                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 4) | (UU_DECODE_CHAR(ptr[1]) >> 2);
                ptr++;
                if (--length == 0)
                    break;

                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 6) | (UU_DECODE_CHAR(ptr[1]));
                ptr += 2;
                length -= 2;
            }
        }
        else
        {
            /* probably padding. skip over it.*/
            ptr++;
        }
    }

    if(*end_found)
        *bytes_read = end - src;
    else
        *bytes_read = ptr - src;
    *bytes_copied = dptr - dst;
    return 0;
}


int Base64Decode(const uint8_t *start, const uint8_t *end, Email_DecodeState *ds)
{
    uint32_t encode_avail = 0, decode_avail = 0 ;
    uint8_t *encode_buf, *decode_buf;
    uint32_t act_encode_size = 0, act_decode_size = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!(ds->b64_state.encode_depth))
    {
        encode_avail = MAX_BUF;
        decode_avail = MAX_BUF;
    }
    else if ((ds->b64_state.encode_depth) < 0)
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        encode_avail = ds->b64_state.encode_depth - ds->b64_state.encode_bytes_read;
        decode_avail = ds->b64_state.decode_depth - ds->b64_state.decode_bytes_read;
    }

    encode_buf = ds->encodeBuf;
    decode_buf = ds->decodeBuf;

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if(encode_avail ==0 || decode_avail ==0 ||
            (!encode_buf) || (!decode_buf))
    {
        ResetEmailDecodeState(ds);
        return DECODE_EXCEEDED;
    }

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of base64 data spanned across packets*/
    if( ds->prev_encoded_bytes )
    {
        if(ds->prev_encoded_bytes > encode_avail)
            ds->prev_encoded_bytes = encode_avail;

        if(ds->prev_encoded_buf)
        {
            prev_bytes = ds->prev_encoded_bytes;
            encode_avail = encode_avail - prev_bytes;
            while(ds->prev_encoded_bytes)
            {
                /* Since this data cannot be more than 3 bytes*/
                encode_buf[i] = ds->prev_encoded_buf[i];
                i++;
                ds->prev_encoded_bytes--;
            }
        }
    }

    if(sf_strip_CRLF(start, (end-start), encode_buf + prev_bytes, encode_avail, &act_encode_size) != 0)
    {
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + prev_bytes;

    i = (act_encode_size)%4 ;

    /* Encoded data should be in multiples of 4. Then we need to wait for the remainder encoded data to
     * successfully decode the base64 data. This happens when base64 data is spanned across packets*/
    if(i)
    {
        ds->prev_encoded_bytes = i;
        act_encode_size = act_encode_size - i;
        ds->prev_encoded_buf = encode_buf + act_encode_size;
    }

    if(sf_base64decode(encode_buf, act_encode_size, decode_buf, decode_avail, &act_decode_size) != 0)
    {
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }
    else if(!act_decode_size && !encode_avail)
    {
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }


    ds->decode_present = 1;
    ds->decodePtr = decode_buf;
    ds->decoded_bytes = act_decode_size;
    ds->b64_state.encode_bytes_read += act_encode_size;
    ds->b64_state.decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}

int QPDecode(const uint8_t *start, const uint8_t *end, Email_DecodeState *ds)
{
    uint32_t encode_avail = 0, decode_avail = 0 ;
    uint8_t *encode_buf, *decode_buf;
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!(ds->qp_state.encode_depth))
    {
        encode_avail = MAX_BUF;
        decode_avail = MAX_BUF;
    }
    else if ((ds->qp_state.encode_depth) < 0)
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        encode_avail = ds->qp_state.encode_depth - ds->qp_state.encode_bytes_read;
        decode_avail = ds->qp_state.decode_depth - ds->qp_state.decode_bytes_read;
    }

    encode_buf = ds->encodeBuf;
    decode_buf = ds->decodeBuf;

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if(encode_avail ==0 || decode_avail ==0 ||
            (!encode_buf) || (!decode_buf))
    {
        ResetEmailDecodeState(ds);
        return DECODE_EXCEEDED;
    }

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of base64 data spanned across packets*/
    if( ds->prev_encoded_bytes )
    {
        if(ds->prev_encoded_bytes > encode_avail)
            ds->prev_encoded_bytes = encode_avail;

        if(ds->prev_encoded_buf)
        {
            prev_bytes = ds->prev_encoded_bytes;
            encode_avail = encode_avail - prev_bytes;
            while(ds->prev_encoded_bytes)
            {
                /* Since this data cannot be more than 3 bytes*/
                encode_buf[i] = ds->prev_encoded_buf[i];
                i++;
                ds->prev_encoded_bytes--;
            }
        }
    }

    if(sf_strip_LWS(start, (end-start), encode_buf + prev_bytes, encode_avail, &act_encode_size) != 0)
    {
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + prev_bytes;

    if(sf_qpdecode((char *)encode_buf, act_encode_size, (char *)decode_buf, decode_avail, &bytes_read, &act_decode_size) != 0)
    {
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }
    else if(!act_decode_size && !encode_avail)
    {
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }


    if(bytes_read < act_encode_size)
    {
        ds->prev_encoded_bytes = (act_encode_size - bytes_read);
        ds->prev_encoded_buf = encode_buf + bytes_read;
        act_encode_size = bytes_read;
    }

    ds->decode_present = 1;
    ds->decodePtr = decode_buf;
    ds->decoded_bytes = act_decode_size;
    ds->qp_state.encode_bytes_read += act_encode_size;
    ds->qp_state.decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}


int UUDecode(const uint8_t *start, const uint8_t *end, Email_DecodeState *ds)
{
    uint32_t encode_avail = 0, decode_avail = 0 ;
    uint8_t *encode_buf, *decode_buf;
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!(ds->uu_state.encode_depth))
    {
        encode_avail = MAX_BUF;
        decode_avail = MAX_BUF;
    }
    else if ((ds->uu_state.encode_depth) < 0)
    {
        ds->uu_state.begin_found = 0;
        return DECODE_EXCEEDED;
    }
    else
    {
        encode_avail = ds->uu_state.encode_depth - ds->uu_state.encode_bytes_read;
        decode_avail = ds->uu_state.decode_depth - ds->uu_state.decode_bytes_read;
    }

    encode_buf = ds->encodeBuf;
    decode_buf = ds->decodeBuf;

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if(encode_avail ==0 || decode_avail ==0 ||
            (!encode_buf) || (!decode_buf))
    {
        ds->uu_state.begin_found = 0;
        ResetEmailDecodeState(ds);
        return DECODE_EXCEEDED;
    }

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of base64 data spanned across packets*/
    if( ds->prev_encoded_bytes )
    {
        if(ds->prev_encoded_bytes > encode_avail)
            ds->prev_encoded_bytes = encode_avail;

        if(ds->prev_encoded_buf)
        {
            prev_bytes = ds->prev_encoded_bytes;
            encode_avail = encode_avail - prev_bytes;
            while(ds->prev_encoded_bytes)
            {
                /* Since this data cannot be more than 3 bytes*/
                encode_buf[i] = ds->prev_encoded_buf[i];
                i++;
                ds->prev_encoded_bytes--;
            }
        }
    }

    if((uint32_t)(end- start) > encode_avail)
        act_encode_size = encode_avail;
    else
        act_encode_size = end - start;


    if(encode_avail > 0)
    {
        if(SafeMemcpy((encode_buf + prev_bytes), start, act_encode_size, encode_buf, (encode_buf+ encode_avail + prev_bytes)) != SAFEMEM_SUCCESS) 
        {
            ResetEmailDecodeState(ds);
            return DECODE_FAIL;
        }
    }

    act_encode_size = act_encode_size + prev_bytes;


    if(sf_uudecode(encode_buf, act_encode_size, decode_buf, decode_avail, &bytes_read, &act_decode_size, 
                &(ds->uu_state.begin_found), &(ds->uu_state.end_found)) != 0)
    {
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }
    else if(!act_decode_size && !encode_avail)
    {
        /* Have insufficient data to decode */
        ResetEmailDecodeState(ds);
        return DECODE_FAIL;
    }

    /* Found the end. No more encoded data */

    if(ds->uu_state.end_found)
    {
        ds->uu_state.end_found = 0;
        ds->uu_state.begin_found = 0;
    }

    if(bytes_read < act_encode_size)
    {
        ds->prev_encoded_bytes = (act_encode_size - bytes_read);
        ds->prev_encoded_buf = encode_buf + bytes_read;
        act_encode_size = bytes_read;
    }

    ds->decode_present = 1;
    ds->decoded_bytes = act_decode_size;
    ds->decodePtr = decode_buf;
    ds->uu_state.encode_bytes_read += act_encode_size;
    ds->uu_state.decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}




int BitEncExtract(const uint8_t *start, const uint8_t *end, Email_DecodeState *ds)
{
    uint32_t bytes_avail = 0;
    uint32_t act_size = 0;

    ClearPrevEncodeBuf(ds);

    if (!(ds->bitenc_state.depth))
    {
        bytes_avail = MAX_BUF;
    }
    else if ((ds->bitenc_state.depth) < 0)
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        bytes_avail = ds->bitenc_state.depth - ds->bitenc_state.bytes_read;
    }

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if(bytes_avail ==0)
    {
        ResetEmailDecodeState(ds);
        return DECODE_EXCEEDED;
    }


    if( (uint32_t)(end-start) < bytes_avail )
    {
        act_size = ( end - start);
    }
    else
    {
        act_size = bytes_avail;
    }

    ds->decode_present = 1;
    ds->decodePtr = (uint8_t *)start;
    ds->decoded_bytes = act_size;
    ds->bitenc_state.bytes_read += act_size;

    return DECODE_SUCCESS;
}

int EmailDecode(const uint8_t *start, const uint8_t *end, Email_DecodeState *ds)
{
    int iRet = DECODE_FAIL;

    switch(ds->decode_type)
    {
        case DECODE_B64:
            iRet = Base64Decode(start, end, ds);
            break;
        case DECODE_QP:
            iRet = QPDecode(start, end, ds);
            break;
        case DECODE_UU:
            iRet = UUDecode(start, end, ds);
            break;
        case DECODE_BITENC:
            iRet = BitEncExtract(start, end, ds);
            break;
        default: 
            break;
    }

    return iRet;
}

