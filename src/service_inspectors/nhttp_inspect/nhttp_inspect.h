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

#ifndef NHTTP_INSPECT_H
#define NHTTP_INSPECT_H

//-------------------------------------------------------------------------
// NHttpInspect class
//-------------------------------------------------------------------------

class NHttpInspect : public Inspector {
public:
    NHttpInspect(bool _test_mode);
    ~NHttpInspect();

    void configure(SnortConfig*, const char*, char *args);
    int verify(SnortConfig*);
    void show(SnortConfig*);
    void eval(Packet*);
    bool enabled();
    void pinit();
    void pterm();

private:
    friend NHttpApi;
    static THREAD_LOCAL NHttpMsgHeader *msgHead;

    // Test mode
    bool test_mode;
    static const char *testInputFile;
    static const char *testOutputPrefix;
    NHttpTestInput *testInput = nullptr;
    FILE *testOut = nullptr;
    int64_t testNumber = 0;
    int64_t fileTestNumber = -1;
};

#endif

