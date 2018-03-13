//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// sf_multi_mpse.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_multi_mpse.h"

#include "search_engines/search_tool.h"
#include "utils/util.h"

struct tPatternRootNode;
struct tPatternList
{
    tMlpPattern pattern;
    void* userData;             /*client/service info */

    tPatternList* nextPattern;
    tPatternRootNode* nextLevelMatcher;
};

/*Root node */
struct tPatternRootNode
{
    snort::SearchTool* patternTree;
    tPatternList* patternList;
    tPatternList* lastPattern;
    unsigned int level;        /*some searches may be specific to levels. Increments from 1 at top
                                  level, */
};

/*Used to track matched patterns. */
struct MatchedPattern
{
    tPatternList* patternNode;
    size_t match_start_pos;
    unsigned int level;
};

static int compareAppUrlPatterns(const void* p1, const void* p2);
static int createTreesRecusively(void* root);
static void destroyTreesRecursively(void* root);
static void dumpTreesRecursively(void* root, int level);
static int addPatternRecursively(void* root, const tMlpPattern** inputPatternList, void* metaData,
    int level);
static int longest_pattern_match(void* id, void*, int match_end_pos, void* data,
    void*);
static int url_pattern_match(void* id, void*, int match_end_pos, void* data, void*);

void* mlpCreate()
{
    tPatternRootNode* root = (tPatternRootNode*)snort_calloc(sizeof(tPatternRootNode));
    root->level = 0;
    return root;
}

/*last pattern should be nullptr */
int mlpAddPattern(void* root, const tMlpPattern** inputPatternList, void* metaData)
{
    return addPatternRecursively(root, inputPatternList, metaData, 0);
}

int mlpProcessPatterns(void* root)
{
    int rvalue;

    rvalue = createTreesRecusively(root);
    if (rvalue)
        destroyTreesRecursively(root);
    return rvalue;
}

void* mlpMatchPatternLongest(void* root, tMlpPattern** inputPatternList)
{
    return mlpMatchPatternCustom(root, inputPatternList, longest_pattern_match);
}

void* mlpMatchPatternUrl(void* root, tMlpPattern** inputPatternList)
{
    return mlpMatchPatternCustom(root, inputPatternList, url_pattern_match);
}

static inline bool match_is_domain_pattern(MatchedPattern mp, const uint8_t* data)
{
    if (!data)
        return false;

    return mp.level != 0 or
           mp.match_start_pos == 0 or
           data[mp.match_start_pos-1] == '.';
}

void* mlpMatchPatternCustom(void* root, tMlpPattern** inputPatternList, int (* callback)(void*,
    void*, int, void*, void*))
{
    MatchedPattern mp = { nullptr,0,0 };
    void* data = nullptr;
    void* tmpData = nullptr;
    tPatternList* patternNode;
    tPatternRootNode* rootNode = (tPatternRootNode*)root;
    tMlpPattern* pattern = *inputPatternList;

    if (!rootNode || !pattern || !pattern->pattern)
        return nullptr;

    mp.level = rootNode->level;

    rootNode->patternTree->find_all((const char*)pattern->pattern,
        pattern->patternSize,
        callback,
        false,
        &mp);

    patternNode = mp.patternNode;
    if (patternNode)
    {
        if (!match_is_domain_pattern(mp, pattern->pattern))
            return nullptr;

        data = patternNode->userData;
        tmpData = mlpMatchPatternCustom(patternNode->nextLevelMatcher, ++inputPatternList,
            callback);
        if (tmpData)
            data = tmpData;
    }

    return data;
}

void mlpDestroy(void* root)
{
    destroyTreesRecursively(root);
}

void mlpDump(void* root)
{
    dumpTreesRecursively(root, 0);
}

/*alphabetically ordering */
static int compareAppUrlPatterns(const void* p1, const void* p2)
{
    const tMlpPattern* pat1 = (const tMlpPattern*)p1;
    const tMlpPattern* pat2 = (const tMlpPattern*)p2;
    int rValue;
    size_t minSize;

    /*first compare patterns by the smaller pattern size, if same then size wins */
    minSize = (pat1->patternSize > pat2->patternSize) ? pat2->patternSize : pat1->patternSize;

    rValue = memcmp(pat1->pattern, pat2->pattern, minSize);
    if (rValue)
        return rValue;

    return ((int)pat1->patternSize - (int)pat2->patternSize);
}

/* Pattern trees are not freed on error because in case of error, caller
 * should call detroyTreesRecursively.
 */
static int createTreesRecusively(void* root)
{
    tPatternRootNode* rootNode = (tPatternRootNode*)root;
    snort::SearchTool* patternMatcher;
    tPatternList* patternNode;

    /* set up the MPSE for url patterns */
    if (!(patternMatcher = rootNode->patternTree = new snort::SearchTool("ac_full", true)))
        return -1;

    for (patternNode = rootNode->patternList;
        patternNode;
        patternNode = patternNode->nextPattern)
    {
        /*recursion into next lower level */
        if (patternNode->nextLevelMatcher)
        {
            if (createTreesRecusively(patternNode->nextLevelMatcher))
                return -1;
        }

        patternMatcher->add(patternNode->pattern.pattern,
            patternNode->pattern.patternSize,
            patternNode,
            false);
    }

    patternMatcher->prep();

    return 0;
}

static void destroyTreesRecursively(void* root)
{
    tPatternRootNode* rootNode = (tPatternRootNode*)root;
    tPatternList* patternNode;

    while ((patternNode = rootNode->patternList))
    {
        /*recursion into next lower level */
        if (patternNode->nextLevelMatcher)
        {
            destroyTreesRecursively(patternNode->nextLevelMatcher);
        }
        rootNode->patternList = patternNode->nextPattern;
        snort_free(patternNode);
    }

    delete rootNode->patternTree;
    snort_free(rootNode);
}

static void dumpTreesRecursively(void* root, int level)
{
    tPatternRootNode* rootNode = (tPatternRootNode*)root;
    tPatternList* patternNode;
    char* offset;

    offset = (char*)snort_calloc(4*level+2);
    if (!offset)
        return;
    memset(offset, ' ', 4*level+1);
    offset[4*level] = '\0';

    for (patternNode = rootNode->patternList;
        patternNode;
        patternNode = patternNode->nextPattern)
    {
        printf("%sPattern %s, size %u, userData %p\n", offset,
            (const char*)patternNode->pattern.pattern,
            (uint32_t)patternNode->pattern.patternSize,
            patternNode->userData);

        /*recursion into next lower level */
        if (patternNode->nextLevelMatcher)
        {
            dumpTreesRecursively(patternNode->nextLevelMatcher, (level+1));
        }
    }
    snort_free(offset);
}

static int longest_pattern_match(void* id, void*, int match_end_pos, void* data,
    void*)
{
    tPatternList* target = (tPatternList*)id;
    MatchedPattern* match = (MatchedPattern*)data;
    int newMatchWins = 0;

    /*printf("LongestMatcher: level %d, match_end_pos: %d, matched %s\n", matches->level, match_end_pos,
       target->pattern.pattern); */

    /*first match */
    if (!match->patternNode)
        newMatchWins = 1;
    /*subsequent longer match */
    else if (match->patternNode->pattern.patternSize < target->pattern.patternSize)
        newMatchWins = 1;

    if (newMatchWins)
    {
        /*printf("new pattern wins\n"); */
        match->patternNode = target;
        match->match_start_pos = match_end_pos - target->pattern.patternSize;
    }

    return 0;
}

static int url_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    tPatternList* target = (tPatternList*)id;
    MatchedPattern* match = (MatchedPattern*)data;
    int newMatchWins = 0;

    /*printf("UrlMatcher: level %d, match_end_pos: %d, matched %s\n", match->level, match_end_pos,
      target->pattern.pattern);
      first match */
    if (!match->patternNode)
        newMatchWins = 1;

    /*subsequent longer match */
    else if (match->patternNode->pattern.patternSize < target->pattern.patternSize)
        newMatchWins = 1;
    else if (match->patternNode->pattern.patternSize == target->pattern.patternSize)
    {
        /*host part matching towards later part is better. This is not designed to prevent
          mis-identifying
          url 'www.spoof_for_google.google.com.phishing.com' as google. */
        if ((match->level == 0) &&
            (match->match_start_pos < (unsigned int)match_end_pos - target->pattern.patternSize))
            newMatchWins = 1;
        /*path part matching towards lower position is better */
        if ((match->level == 1) &&
            (match->match_start_pos > (unsigned int)match_end_pos - target->pattern.patternSize))
            newMatchWins = 1;
    }

    if (newMatchWins)
    {
        /*printf("new pattern wins\n"); */
        match->patternNode = target;
        match->match_start_pos = match_end_pos - target->pattern.patternSize;
    }

    return 0;
}

static int addPatternRecursively(void* root, const tMlpPattern** inputPatternList, void* metaData,
    int level)
{
    tPatternRootNode* rootNode = (tPatternRootNode*)root;
    tPatternList* prevNode = nullptr;
    tPatternList* patternList;
    tPatternList* newNode;
    const tMlpPattern* nextPattern;
    const tMlpPattern* patterns = *inputPatternList;

    if (!rootNode || !patterns || !patterns->pattern)
        return -1;

    for (patternList = rootNode->patternList;
        patternList;
        prevNode = patternList, patternList = patternList->nextPattern)
    {
        int rvalue = compareAppUrlPatterns(patterns, patternList);

        if (rvalue < 0)
            continue;

        if (rvalue == 0)
        {
            nextPattern = *(inputPatternList+1);

            if (!nextPattern || !nextPattern->pattern)
            {
                /*overriding any previous userData. */
                patternList->userData = metaData;
                return 0;
            }
            return addPatternRecursively(patternList->nextLevelMatcher, inputPatternList+1,
                metaData, level+1);
        }
        break;
    }

    /*allocate and initialize a new node */
    newNode = (tPatternList*)snort_calloc(sizeof(tPatternList));
    newNode->pattern.pattern = patterns->pattern;
    newNode->pattern.patternSize = patterns->patternSize;
    newNode->nextLevelMatcher = (tPatternRootNode*)snort_calloc(sizeof(tPatternRootNode));
    newNode->nextLevelMatcher->level = rootNode->level+1;

    /*insert the new node */
    if (!prevNode)
    {
        /*insert as first node since either this is the only node, or this is lexically smallest.
           */
        newNode->nextPattern = rootNode->patternList;
        rootNode->patternList = newNode;
    }
    else
    {
        /*insert after previous node since either there is either a biggest node after prevNode or
          newNode is lexically largest. */
        newNode->nextPattern = prevNode->nextPattern;
        prevNode->nextPattern = newNode;
    }

    /*move down the new node */
    nextPattern = *(inputPatternList+1);
    if (!nextPattern || !nextPattern->pattern)
    {
        newNode->userData = metaData;
    }
    else
    {
        addPatternRecursively(newNode->nextLevelMatcher, inputPatternList+1, metaData, level+1);
    }

    return 0;
}

/**returns pattern tree at the level where inputPatternList runs out.
 */
void* mlpGetPatternMatcherTree(void* root, tMlpPattern** inputPatternList)
{
    MatchedPattern mp = { nullptr,0,0 };
    tPatternList* patternNode;
    tPatternRootNode* rootNode = (tPatternRootNode*)root;
    tMlpPattern* pattern = *inputPatternList;

    if (!rootNode || !pattern || !pattern->pattern)
        return nullptr;

    mp.level = rootNode->level;

    rootNode->patternTree->find_all((const char*)pattern->pattern,
        pattern->patternSize,
        longest_pattern_match,
        false,
        &mp);

    patternNode = mp.patternNode;
    if (patternNode)
    {
        ++inputPatternList;
        if (*inputPatternList && (*inputPatternList)->pattern)
        {
            return mlpMatchPatternCustom(patternNode->nextLevelMatcher, inputPatternList,
                longest_pattern_match);
        }
        return patternNode->nextLevelMatcher;
    }

    return nullptr;
}

