//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

/**
**  @file       hi_ui_iis_unicode_map.c
**
**  @author     Daniel Roelker <droelker@atlas.cs.cuc.edu>
**
**  @brief      Functions for parsing the unicode map file
**
**  This file contains the routines for parsing generated IIS unicode
**  maps.  We read in the map, find where the codepage is located in
**  the map, and convert the codepoint maps, and store in the supplied
**  array.
**
**  NOTES
**    -  Initial development.  DJR
*/

#include "hi_ui_iis_unicode_map.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sstream>
#include <string>

#include "utils/util.h"
#include "hi_ui_config.h"
#include "hi_return_codes.h"

#define MAX_BUFFER 50000
#define CODEPAGE_SEPARATORS  " \t\n\r"
#define CODEPOINT_SEPARATORS ": \n\r"

/*
**  NAME
**    FindCodePage::
*/
/**
**  Locate the codepage mapping the IIS Unicode Map file.
**
**  We iterate through the file lines until we get to the codepage
**  reference.  We then return that it was found successfully, and
**  the FILE pointer is located on the codepoint mapping line.
**
**  @param fFile     the codemap file pointer
**  @param iCodePage the codepage number
**
**  @return int
**
**  @retval HI_FATAL_ERR  Did not find the codepage listing.
**  @retval HI_SUCCESS    function successful
*/
static int FindCodePage(FILE* fFile, int iCodePage)
{
    static char buffer[MAX_BUFFER];
    char* pcToken;
    int iCodePageTest;
    char* pcEnd;
    char* pcPtr;

    while (fgets(buffer, MAX_BUFFER, fFile))
    {
        pcToken = strtok_r(buffer, CODEPAGE_SEPARATORS, &pcPtr);
        if (!pcToken)
            continue;

        if (pcToken[0] == '#')
            continue;

        /*
        **  Is this a codepage or the beginning of a codemap
        */
        if (strchr(pcToken, ':'))
            continue;

        /*
        **  So we now have the beginning of a codepage number
        */
        iCodePageTest = strtol(pcToken, &pcEnd, 10);
        if (*pcEnd)
            continue;

        if (iCodePageTest == iCodePage)
            return HI_SUCCESS;
    }

    return HI_FATAL_ERR;
}

/*
**  NAME
**    MapCodePoints::
*/
/**
**  Read the codepoint mapping and covert to codepoint and ASCII.
**
**  This is where the bulk of the work is done.  We read in 9 bytes at a time
**  because the mappings are in chunks of 8 (+1 for the NULL at the end).  The
**  chunks are as follows:
**
**  xxxx:xx (the first set of 4 is the codepoint, the second set is the ASCII
**  representation)
**
**  We then convert and check these values before storing them in the
**  supplied array.
**
**  @param fFile           the unicode map file pointer
**  @param iis_unicode_map the array to store the mappings in
**
**  @return integer
**
**  @retval HI_FATAL_ERR there was an error while parsing the file
**  @retval HI_SUCCESS   function was successful
*/
static int MapCodePoints(FILE* fFile, uint8_t* iis_unicode_map)
{
    char buffer[9];
    char* pcPtr;
    char* pcEnd;
    char* pcToken;
    char* pcCodePoint;
    char* pcAsciiMap;
    int iCodePoint;
    int iAsciiMap;

    /*
    **  We should now be pointing to the beginning of the codemap area for
    **  the selected codepage.
    */
    while (fgets(buffer, 9, fFile))
    {
        pcToken = strtok_r(buffer, CODEPAGE_SEPARATORS, &pcPtr);
        if (!pcToken)
        {
            return HI_SUCCESS;
        }

        pcCodePoint = strtok_r(pcToken, CODEPOINT_SEPARATORS, &pcPtr);
        if (!pcCodePoint)
            return HI_FATAL_ERR;

        pcAsciiMap = strtok_r(NULL, CODEPOINT_SEPARATORS, &pcPtr);
        if (!pcAsciiMap)
            return HI_FATAL_ERR;

        iCodePoint = strtol(pcCodePoint, &pcEnd, 16);
        if (*pcEnd)
        {
            return HI_FATAL_ERR;
        }

        if (iCodePoint < 0 || iCodePoint > 65535)
        {
            return HI_FATAL_ERR;
        }

        iAsciiMap = strtol(pcAsciiMap, &pcEnd, 16);
        if (*pcEnd)
        {
            return HI_FATAL_ERR;
        }

        if (iAsciiMap < 0 || iAsciiMap > 0x7f)
        {
            return HI_FATAL_ERR;
        }

        iis_unicode_map[iCodePoint] = iAsciiMap;

        //printf("** iis_unicode_map[%s] = %s\n", pcCodePoint, pcAsciiMap);
        //printf("** iis_unicode_map[%.2x] = %.2x\n", iCodePoint,
        //       (u_char)iAsciiMap);
    }

    return HI_FATAL_ERR;
}

/*
**  NAME
**    hi_ui_parse_iis_unicode_map::
*/
/**
**  Parses an IIS Unicode Map file and store in the supplied array.
**
**  This routine allocates the necessary memory to store the array values
**  in, and parses the supplied filename.
**
**  @param iis_unicode_map  double pointer so we can allocate the memory
**  @param filename         the name of the file to open and parse
**  @param iCodePage        the codpage number to read the mappings from
**
**  @return integer
**
**  @retval HI_INVALID ARG     invalid argument
**  @retval HI_MEM_ALLOC_FAIL  memory allocation failed
**  @retval HI_INVALID_FILE    Could not open the supplied filename
**  @retval HI_SUCCESS         function was successful
*/
int hi_ui_parse_iis_unicode_map(uint8_t** iis_unicode_map, char* filename,
    int iCodePage)
{
    int iRet;
    FILE* fFile;

    if (!filename || iCodePage < 0)
    {
        return HI_INVALID_ARG;
    }

    fFile = fopen(filename, "r");
    if (fFile == NULL)
    {
        /*
        **  Couldn't open the file
        */
        return HI_INVALID_FILE;
    }

    *iis_unicode_map = (uint8_t*)snort_alloc(sizeof(uint8_t)*65536);
    memset(*iis_unicode_map, HI_UI_NON_ASCII_CODEPOINT, (sizeof(uint8_t)*65536));

    /*
    **  Find the correct codepage
    */
    iRet = FindCodePage(fFile, iCodePage);
    if (iRet)
    {
        //printf("** Did not find codepage\n");
        fclose(fFile);
        return iRet;
    }

    iRet = MapCodePoints(fFile, *iis_unicode_map);
    if (iRet)
    {
        //printf("** Error while parsing codepage.\n");
        fclose(fFile);
        return iRet;
    }

    fclose(fFile);
    return HI_SUCCESS;
}

// update the default unicode map here
// page 1252 is us english
// map is just a single string of tokens of the form
// xxxx:xx (xxxx = unicode, xx = ascii char)
#define default_unicode_page 1252
#define default_unicode_map \
    "0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63    010c:43 010d:63 010e:44 010f:64 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45    0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48    0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49    0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c    0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f    0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53    015f:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55    016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0179:5a    017b:5a 017c:7a 0180:62 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75    01b6:7a 01c0:7c 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55    01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47    01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27    02c4:5e 02c8:27 02cb:60 02cd:5f 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 037e:3b 0393:47    0398:54 03a3:53 03a6:46 03a9:4f 03b1:61 03b4:64 03b5:65 03c0:70 03c3:73 03c4:74 03c6:66 04bb:68    0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2017:3d    2032:27 2035:60 2044:2f 2074:34 2075:35 2076:36 2077:37 2078:38 207f:6e 2080:30 2081:31 2082:32    2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20a7:50 2102:43 2107:45 210a:67 210b:48    210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:50 2119:50 211a:51 211b:52    211c:52 211d:52 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d    2134:6f 2212:2d 2215:2f 2216:5c 2217:2a 221a:76 221e:38 2223:7c 2229:6e 2236:3a 223c:7e 2261:3d    2264:3d 2265:3d 2303:5e 2320:28 2321:29 2329:3c 232a:3e 2500:2d 250c:2b 2510:2b 2514:2b 2518:2b    251c:2b 252c:2d 2534:2d 253c:2b 2550:2d 2552:2b 2553:2b 2554:2b 2555:2b 2556:2b 2557:2b 2558:2b    2559:2b 255a:2b 255b:2b 255c:2b 255d:2b 2564:2d 2565:2d 2566:2d 2567:2d 2568:2d 2569:2d 256a:2b    256b:2b 256c:2b 2584:5f 2758:7c 3000:20 3008:3c 3009:3e 301a:5b 301b:5d ff01:21 ff02:22 ff03:23    ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f    ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b    ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48    ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54    ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60    ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c    ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78    ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e"

bool get_default_unicode_map(uint8_t*& map, int& page)
{
    page = default_unicode_page;
    // FIXIT-M This certainly looks wrong. Why isn't the background value for this table
    // initialized to HI_UI_NON_ASCII_CODEPOINT instead of zero? Compare with
    // hi_ui_parse_iis_unicode_map() above.
    map = (uint8_t*)snort_calloc(65536, sizeof(uint8_t));

    std::stringstream ss(default_unicode_map);
    std::string tok;

    while ( ss >> tok )
    {
        unsigned ucode = strtol(tok.c_str(), nullptr, 16);
        unsigned ascii = strtol(tok.c_str()+5, nullptr, 16);

        if ( ucode > 65535 || ascii > 127 )
        {
            snort_free(map);
            map = nullptr;
            return false;
        }
        map[ucode] = ascii;
    }
    return true;
}

