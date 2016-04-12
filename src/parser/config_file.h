//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#ifndef CONFIG_FILE_H
#define CONFIG_FILE_H

#include "main/snort_types.h"
#include "main/policy.h"

struct SnortConfig;

const char* get_snort_conf();
const char* get_snort_conf_dir();

void ConfigAlertBeforePass(SnortConfig*, const char*);
void ConfigChecksumDrop(SnortConfig*, const char*);
void ConfigChecksumMode(SnortConfig*, const char*);
void ConfigChrootDir(SnortConfig*, const char*);
void ConfigCreatePidFile(SnortConfig*, const char*);
void ConfigDaemon(SnortConfig*, const char*);
void ConfigDecodeDataLink(SnortConfig*, const char*);
void ConfigDumpCharsOnly(SnortConfig*, const char*);
void ConfigDumpPayload(SnortConfig*, const char*);
void ConfigDumpPayloadVerbose(SnortConfig*, const char*);
void ConfigLogDir(SnortConfig*, const char*);
void ConfigDirtyPig(SnortConfig*, const char*);
void ConfigNoLoggingTimestamps(SnortConfig*, const char*);
void ConfigObfuscate(SnortConfig*, const char*);
void ConfigObfuscationMask(SnortConfig*, const char*);
void ConfigQuiet(SnortConfig*, const char*);
void ConfigShowYear(SnortConfig*, const char*);
void ConfigTreatDropAsAlert(SnortConfig*, const char*);
void ConfigTreatDropAsIgnore(SnortConfig*, const char*);
void ConfigProcessAllEvents(SnortConfig*, const char*);
void ConfigUtc(SnortConfig*, const char*);
void ConfigVerbose(SnortConfig*, const char*);
void ConfigPluginPath(SnortConfig*, const char*);
void ConfigScriptPaths(SnortConfig*, const char*);
void ConfigDstMac(SnortConfig*, const char*);

void ConfigSetGid(SnortConfig*, const char*);
void ConfigSetUid(SnortConfig*, const char*);
void ConfigUmask(SnortConfig*, const char*);
void ConfigTunnelVerdicts(SnortConfig*, const char*);
void config_syslog(SnortConfig* sc, const char*);
void config_daemon(SnortConfig* sc, const char*);
void config_alert_mode(SnortConfig* sc, const char*);
void config_log_mode(SnortConfig* sc, const char*);
void config_conf(SnortConfig*, const char*);
void SetSnortConfDir(const char*);

#endif

