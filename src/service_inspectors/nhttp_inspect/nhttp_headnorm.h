/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      HeaderNormalizer class declaration
//

#ifndef NHTTP_HEADNORM_H
#define NHTTP_HEADNORM_H


//-------------------------------------------------------------------------
// HeaderNormalizer class
// Strategies for normalizing HTTP header field values
//-------------------------------------------------------------------------

// Three normalization functions per HeaderNormalizer seems likely to be enough. Nothing subtle will break if you choose to expand it to four or more. Just a whole bunch of
// signatures and initializers to update.
// When defining a HeaderNormalizer don't leave holes in the normalizer list. E.g. if you have two normalizers they must be first and second. If you do first and third
// instead it won't explode but the third one won't be used either.

class HeaderNormalizer {
public:
    constexpr HeaderNormalizer(NHttpEnums::NormFormat _format, bool _concatenateRepeats, bool _infractRepeats, int32_t (*f1)(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void*),
       const void *f1Arg, int32_t (*f2)(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void*), const void *f2Arg, int32_t (*f3)(const uint8_t*, int32_t, uint8_t*, uint64_t&,
       const void*), const void *f3Arg) :
          format(_format),
          concatenateRepeats(_concatenateRepeats),
          infractRepeats(_infractRepeats),
          normalizer { f1, f2, f3 },
          normArg { f1Arg, f2Arg, f3Arg },
          numNormalizers((f1 != nullptr) + (f1 != nullptr)*(f2 != nullptr) + (f1 != nullptr)*(f2 != nullptr)*(f3 != nullptr)) {};
    void normalize(ScratchPad &scratchPad, uint64_t &infractions, NHttpEnums::HeaderId headId, const NHttpEnums::HeaderId headerNameId[], const field headerName[], int32_t numHeaders,
       field &resultField) const;
    NHttpEnums::NormFormat getFormat() const {return format;};

private:
    int32_t deriveHeaderContent(const uint8_t *value, int32_t length, uint8_t *buffer) const;

    const NHttpEnums::NormFormat format;
    const bool concatenateRepeats;
    const bool infractRepeats;
    int32_t (* const normalizer[3])(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void*);
    const void * normArg[3];
    const int numNormalizers;
};

// Normalizer functions

int32_t normDecimalInteger(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void* notUsed);
int32_t norm2Lower(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void* notUsed);
int32_t normStrCode(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void*);
int32_t normSeqStrCode(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void*);

#endif


