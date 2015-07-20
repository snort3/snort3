//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "trough.h"

#include <fnmatch.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>

#include "parser/cmd_line.h"
#include "parser/parser.h"
#include "utils/sflsq.h"
#include "packet_io/sfdaq.h"
#include "utils/util.h"
#include "main/snort_config.h"

struct PcapReadObject
{
    SourceType type;
    char* arg;
    char* filter;
};

static SF_LIST* pcap_object_list = NULL;
static SF_QUEUE* pcap_queue = NULL;
static SF_QUEUE* pcap_save_queue = NULL;
static char* pcap_filter = NULL;
static long int pcap_loop_count = 0;
static unsigned file_count = 0;

/* very slow sort - do not use at runtime! */
static SF_LIST* SortDirectory(const char* path)
{
    SF_LIST* dir_entries;
    DIR* dir;
    struct dirent* direntry;
    int ret = 0;

    if (path == NULL)
        return NULL;

    dir_entries = sflist_new();
    if (dir_entries == NULL)
    {
        ErrorMessage("Could not allocate new list for directory entries\n");
        return NULL;
    }

    dir = opendir(path);
    if (dir == NULL)
    {
        ErrorMessage("Error opening directory: %s: %s\n",
            path, get_error(errno));
        sflist_free_all(dir_entries, free);
        return NULL;
    }

    /* Reset errno since we'll be checking it unconditionally */
    errno = 0;

    while ((direntry = readdir(dir)) != NULL)  // main thread only
    {
        char* node_entry_name, * dir_entry_name;
        SF_LNODE* node;
        NODE_DATA ndata;

        dir_entry_name = SnortStrdup(direntry->d_name);

        for (ndata = sflist_first(dir_entries, &node);
            ndata != NULL;
            ndata = sflist_next(&node))
        {
            node_entry_name = (char*)ndata;
            if (strcmp(dir_entry_name, node_entry_name) < 0)
                break;
        }

        if (node == NULL)
            ret = sflist_add_tail(dir_entries, (NODE_DATA)dir_entry_name);
        else
            ret = sflist_add_before(dir_entries, node, (NODE_DATA)dir_entry_name);

        if (ret == -1)
        {
            ErrorMessage("Error adding directory entry to list\n");
            sflist_free_all(dir_entries, free);
            closedir(dir);
            return NULL;
        }
    }

    if (errno != 0)
    {
        ErrorMessage("Error reading directory: %s: %s\n",
            path, get_error(errno));
        errno = 0;
        sflist_free_all(dir_entries, free);
        closedir(dir);
        return NULL;
    }

    closedir(dir);

    return dir_entries;
}

int GetFilesUnderDir(const char* path, SF_QUEUE* dir_queue, const char* filter)
{
    SF_LIST* dir_entries;
    char* direntry;
    int ret = 0;
    int num_files = 0;

    if ((path == NULL) || (dir_queue == NULL))
        return -1;

    dir_entries = SortDirectory(path);
    if (dir_entries == NULL)
    {
        ErrorMessage("Error sorting entries in directory: %s\n", path);
        return -1;
    }
    SF_LNODE* cursor;

    for (direntry = (char*)sflist_first(dir_entries, &cursor);
        direntry != NULL;
        direntry = (char*)sflist_next(&cursor))
    {
        char path_buf[PATH_MAX];
        struct stat file_stat;

        /* Don't look at dot files */
        if (strncmp(".", direntry, 1) == 0)
            continue;

        ret = SnortSnprintf(path_buf, PATH_MAX, "%s%s%s",
            path, path[strlen(path) - 1] == '/' ? "" : "/", direntry);
        if (ret == SNORT_SNPRINTF_TRUNCATION)
        {
            ErrorMessage("Error copying file to buffer: Path too long\n");
            sflist_free_all(dir_entries, free);
            return -1;
        }
        else if (ret != SNORT_SNPRINTF_SUCCESS)
        {
            ErrorMessage("Error copying file to buffer\n");
            sflist_free_all(dir_entries, free);
            return -1;
        }

        ret = stat(path_buf, &file_stat);
        if (ret == -1)
        {
            ErrorMessage("Could not stat file: %s: %s\n",
                path_buf, get_error(errno));
            continue;
        }

        if (file_stat.st_mode & S_IFDIR)
        {
            ret = GetFilesUnderDir(path_buf, dir_queue, filter);
            if (ret == -1)
            {
                sflist_free_all(dir_entries, free);
                return -1;
            }

            num_files += ret;
        }
        else if (file_stat.st_mode & S_IFREG)
        {
            if ((filter == NULL) || (fnmatch(filter, direntry, 0) == 0))
            {
                char* file = SnortStrdup(path_buf);

                ret = sfqueue_add(dir_queue, (NODE_DATA)file);
                if (ret == -1)
                {
                    ErrorMessage("Could not append item to list: %s\n", file);
                    free(file);
                    sflist_free_all(dir_entries, free);
                    return -1;
                }

                num_files++;
            }
        }
    }

    sflist_free_all(dir_entries, free);

    return num_files;
}

/*****************************************************************
 * Function: GetPcaps()
 *
 * This function takes a list of pcap types and arguments from
 * the command line, parses them depending on type and puts them
 * in a user supplied queue. The pcap object list will contain
 * PcapReadObject structures.  The returned queue contains
 * strings representing paths to pcaps.
 *
 * returns -1 on error and 0 on success
 *
 ****************************************************************/
static int GetPcaps(SF_LIST* pol, SF_QUEUE* pcap_queue)
{
    PcapReadObject* pro = NULL;
    char* arg = NULL;
    char* filter = NULL;
    int ret = 0;

    if ((pol == NULL) || (pcap_queue == NULL))
        return -1;

    SF_LNODE* cursor;

    for (pro = (PcapReadObject*)sflist_first(pol, &cursor);
        pro != NULL;
        pro = (PcapReadObject*)sflist_next(&cursor))
    {
        arg = pro->arg;
        filter = pro->filter;

        switch (pro->type)
        {
        case SOURCE_FILE_LIST:
            /* arg should be a file with a list of pcaps in it */
        {
            FILE* pcap_file = NULL;
            char* pcap = NULL;
            char path_buf[4096];           /* max chars we'll accept for a path */

            pcap_file = fopen(arg, "r");
            if (pcap_file == NULL)
            {
                ErrorMessage("Could not open pcap list file: %s: %s\n",
                    arg, get_error(errno));
                return -1;
            }

            while (fgets(path_buf, sizeof(path_buf), pcap_file) != NULL)
            {
                char* path_buf_ptr, * path_buf_end;
                struct stat stat_buf;

                path_buf[sizeof(path_buf) - 1] = '\0';
                path_buf_ptr = &path_buf[0];
                path_buf_end = path_buf_ptr + strlen(path_buf_ptr);

                /* move past spaces if any */
                while (isspace((int)*path_buf_ptr))
                    path_buf_ptr++;

                /* if nothing but spaces on line, continue */
                if (*path_buf_ptr == '\0')
                    continue;

                /* get rid of trailing spaces */
                while ((path_buf_end > path_buf_ptr) &&
                    (isspace((int)*(path_buf_end - 1))))
                    path_buf_end--;

                *path_buf_end = '\0';

                /* do a quick check to make sure file exists */
                if (SnortConfig::read_mode() && stat(path_buf_ptr, &stat_buf) == -1)
                {
                    ErrorMessage("Error getting stat on pcap file: %s: %s\n",
                        path_buf_ptr, get_error(errno));
                    fclose(pcap_file);
                    return -1;
                }
                else if (SnortConfig::read_mode() && stat_buf.st_mode & S_IFDIR)
                {
                    ret = GetFilesUnderDir(path_buf_ptr, pcap_queue, filter);
                    if (ret == -1)
                    {
                        ErrorMessage("Error getting pcaps under dir: %s\n", path_buf_ptr);
                        fclose(pcap_file);
                        return -1;
                    }
                }
                else if (!SnortConfig::read_mode() || stat_buf.st_mode & S_IFREG)
                {
                    if ((filter == NULL) || (fnmatch(filter, path_buf_ptr, 0) == 0))
                    {
                        pcap = SnortStrdup(path_buf_ptr);
                        ret = sfqueue_add(pcap_queue, (NODE_DATA)pcap);
                        if (ret == -1)
                        {
                            ErrorMessage("Could not insert pcap into list: %s\n", pcap);
                            free(pcap);
                            fclose(pcap_file);
                            return -1;
                        }
                    }
                }
                else
                {
                    ErrorMessage(
                        "Specified entry in \'%s\' is not a regular file or directory: %s\n",
                        arg, path_buf_ptr);
                    fclose(pcap_file);
                    return -1;
                }
            }

            fclose(pcap_file);
        }

        break;

        case SOURCE_LIST:
            /* arg should be a space separated list of pcaps */
        {
            char* tmp = NULL;
            char* pcap = NULL;
            struct stat stat_buf;

            tmp = strtok_r(arg, " ", &arg);
            if (tmp == NULL)
            {
                ErrorMessage("No pcaps specified in pcap list\n");
                return -1;
            }

            do
            {
                /* do a quick check to make sure file exists */
                if (SnortConfig::read_mode() && stat(tmp, &stat_buf) == -1)
                {
                    ErrorMessage("Error getting stat on file: %s: %s\n",
                        tmp, get_error(errno));
                    return -1;
                }
                else if (SnortConfig::read_mode() && !(stat_buf.st_mode & (S_IFREG|S_IFIFO)))
                {
                    ErrorMessage("Specified pcap is not a regular file: %s\n", tmp);
                    return -1;
                }

                pcap = SnortStrdup(tmp);
                ret = sfqueue_add(pcap_queue, (NODE_DATA)pcap);
                if (ret == -1)
                {
                    ErrorMessage("Could not insert pcap into list: %s\n", pcap);
                    free(pcap);
                    return -1;
                }
            }
            while ((tmp = strtok_r(NULL, " ", &arg)) != NULL);
        }

        break;

        case SOURCE_DIR:
            /* arg should be a directory name */
            ret = GetFilesUnderDir(arg, pcap_queue, filter);
            if (ret == -1)
            {
                ErrorMessage("Error getting pcaps under dir: %s\n", arg);
                return -1;
            }

            break;

        default:
            ParseError("Bad read multiple pcaps type");
            break;
        }
    }

    return 0;
}

long Trough_GetLoopCount()
{ return pcap_loop_count; }

void Trough_SetLoopCount(long int c)
{ pcap_loop_count = c; }

void Trough_SetFilter(const char* f)
{
    if (pcap_filter != NULL)
        free(pcap_filter);

    pcap_filter = f ? SnortStrdup(f) : NULL;
}

void Trough_Multi(SourceType type, const char* list)
{
    PcapReadObject* pro;

    if (pcap_object_list == NULL)
    {
        pcap_object_list = sflist_new();
        if (pcap_object_list == NULL)
            FatalError("Could not allocate list to store pcaps\n");
    }

    pro = (PcapReadObject*)SnortAlloc(sizeof(PcapReadObject));
    pro->type = type;
    pro->arg = SnortStrdup(list);
    if (pcap_filter != NULL)
        pro->filter = SnortStrdup(pcap_filter);
    else
        pro->filter = NULL;

    if (sflist_add_tail(pcap_object_list, (NODE_DATA)pro) == -1)
        FatalError("Could not add pcap object to list: %s\n", list);
}

void Trough_SetUp(void)
{
    if (pcap_object_list != NULL)
    {
        if (sflist_count(pcap_object_list) == 0)
        {
            sflist_free_all(pcap_object_list, NULL);
            FatalError("No pcaps specified.\n");
        }

        pcap_queue = sfqueue_new();
        pcap_save_queue = sfqueue_new();
        if ((pcap_queue == NULL) || (pcap_save_queue == NULL))
            FatalError("Could not allocate pcap queues.\n");

        if (GetPcaps(pcap_object_list, pcap_queue) == -1)
            FatalError("Error getting pcaps.\n");

        if (sfqueue_count(pcap_queue) == 0)
            FatalError("No pcaps found.\n");

        /* free pcap list used to get params */
        while (sflist_count(pcap_object_list) > 0)
        {
            PcapReadObject* pro = (PcapReadObject*)sflist_remove_head(pcap_object_list);
            if (pro == NULL)
                FatalError("Failed to remove pcap item from list.\n");

            if (pro->arg != NULL)
                free(pro->arg);

            if (pro->filter != NULL)
                free(pro->filter);

            free(pro);
        }

        sflist_free_all(pcap_object_list, NULL);
        pcap_object_list = NULL;
    }
    if (pcap_filter != NULL)
    {
        free(pcap_filter);
        pcap_filter = NULL;
    }
}

int Trough_CleanUp(void)
{
    /* clean up pcap queues */
    if (pcap_queue != NULL)
        sfqueue_free_all(pcap_queue, free);

    if (pcap_save_queue != NULL)
        sfqueue_free_all(pcap_save_queue, free);

    return 0;
}

const char* Trough_First(void)
{
    const char* pcap = (char*)sfqueue_remove(pcap_queue);

    if ( !pcap )
        return pcap;

    if ( sfqueue_add(pcap_save_queue, (NODE_DATA)pcap) == -1 )
        FatalError("Could not add pcap to saved list\n");

    file_count++;
    return pcap;
}

bool Trough_Next(void)
{
    if ( sfqueue_count(pcap_queue) > 0 )
        return true;

    if ( pcap_loop_count > 0 )
    {
        if ( --pcap_loop_count )
        {
            SF_QUEUE* tmp;

            /* switch pcap lists */
            tmp = pcap_queue;
            pcap_queue = pcap_save_queue;
            pcap_save_queue = tmp;

            return true;
        }
    }
    return false;
}

unsigned Trough_GetFileCount()
{
    return file_count;
}

unsigned Trough_GetQCount(void)
{
    return sfqueue_count(pcap_queue);
}

