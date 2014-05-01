/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef CONFIG_FILE_H
#define CONFIG_FILE_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "main/snort_config.h"
#include "snort_types.h"
#include "snort.h"

void ConfigAutogenPreprocDecoderRules(SnortConfig*);
void ConfigAlertBeforePass(SnortConfig*, const char*);
void ConfigChecksumDrop(SnortConfig*, const char*);
void ConfigChecksumMode(SnortConfig*, const char*);
void ConfigChrootDir(SnortConfig*, const char*);
void ConfigCreatePidFile(SnortConfig*, const char*);
void ConfigDaemon(SnortConfig*, const char*);
void ConfigDecodeDataLink(SnortConfig*, const char*);
void ConfigDetectionFilter(SnortConfig*, const char*);
void ConfigDumpCharsOnly(SnortConfig*, const char*);
void ConfigDumpPayload(SnortConfig*, const char*);
void ConfigDumpPayloadVerbose(SnortConfig*, const char*);
void ConfigGTPDecoding(SnortConfig*sc, const char*args);
void ConfigIgnorePorts(SnortConfig*, const char*);
void ConfigLogDir(SnortConfig*, const char*);
void ConfigDaqType(SnortConfig*, const char*);
void ConfigDaqMode(SnortConfig*, const char*);
void ConfigDaqVar(SnortConfig*, const char*);
void ConfigDaqDir(SnortConfig*, const char*);
void ConfigDirtyPig(SnortConfig*, const char*);
void ConfigNoLog(SnortConfig*, const char*);
void ConfigNoLoggingTimestamps(SnortConfig*, const char*);
void ConfigObfuscate(SnortConfig*, const char*);
void ConfigObfuscationMask(SnortConfig*, const char*);
void ConfigPacketSnaplen(SnortConfig*, const char*);
void ConfigPerfFile(SnortConfig*sc, const char*);
void ConfigPidPath(SnortConfig*, const char*);
void ConfigPolicyVersion(SnortConfig*, const char* base, const char* target);
#ifdef PERF_PROFILING
void _ConfigProfilePreprocs(SnortConfig*, const char*);
void _ConfigProfileRules(SnortConfig*, const char*);
void ConfigProfilePreprocs(SnortConfig*, const char*);
void ConfigProfileRules(SnortConfig*, const char*);
#endif
void ConfigQuiet(SnortConfig*, const char*);
void ConfigSetGid(SnortConfig*, const char*);
void ConfigSetUid(SnortConfig*, const char*);
void ConfigShowYear(SnortConfig*, const char*);
void ConfigSoRuleMemcap(SnortConfig*, const char*);
#ifdef TIMESTATS
void ConfigTimestatsInterval(SnortConfig*, const char*);
#endif
void ConfigTreatDropAsAlert(SnortConfig*, const char*);
void ConfigTreatDropAsIgnore(SnortConfig*, const char*);
void ConfigProcessAllEvents(SnortConfig*, const char*);
void ConfigUmask(SnortConfig*, const char*);
void ConfigUtc(SnortConfig*, const char*);
void ConfigVerbose(SnortConfig*, const char*);
void ConfigControlSocketDirectory(SnortConfig*, const char*);
void ConfigTunnelVerdicts(SnortConfig*, const char*);
void ConfigProfiling(SnortConfig*);
void ConfigPluginPath(SnortConfig*, const char*);
void ConfigScriptPath(SnortConfig*, const char*);
void ConfigDstMac(SnortConfig*, const char*);
PolicyMode GetPolicyMode(PolicyMode);
void ConfigIgnorePorts(SnortConfig*, int protocol, const char* ports);

#endif

