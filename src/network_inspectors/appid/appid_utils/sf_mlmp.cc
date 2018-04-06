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

// sf_mlmp.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_mlmp.h"

#include "search_engines/search_tool.h"
#include "utils/util.h"

struct tPatternNode
{
    tMlmpPattern pattern;
    void* userData;             /*client/service info */

    /**part number. Should start from 1. Ordering of parts does not matter in the sense
     * part 1 may appear after part 2 in payload.*/
    uint32_t partNum;

    /**Total number of parts.*/
    uint32_t partTotal;

    /**Unique non-zero identifier to tie parts of a multi-part patterns together. */
    uint32_t patternId;

    tPatternNode* nextPattern;
};

struct tPatternPrimaryNode
{
    tPatternNode patternNode;

    tPatternPrimaryNode* nextPrimaryNode;

    /*Tree node for next level. Present only in primary pattern node i.e.  */
    tMlmpTree* nextLevelMatcher;
};

/*Node for mlmp tree */
struct tMlmpTree
{
    snort::SearchTool* patternTree;
    tPatternPrimaryNode* patternList;
    uint32_t level;
};

/*Used to track matched patterns. */
struct tMatchedPatternList
{
    tPatternNode* patternNode;
    size_t match_start_pos;
    /*uint32_t level; */
    tMatchedPatternList* next;
};

static int compareMlmpPatterns(const void* p1, const void* p2);
static int createTreesRecusively(tMlmpTree* root);
static void destroyTreesRecursively(tMlmpTree* root);
static int addPatternRecursively(tMlmpTree* root, const tMlmpPattern* inputPatternList,
    void* metaData, uint32_t level);
static tPatternNode* urlPatternSelector(const tMatchedPatternList* matchList, const
    uint8_t* payload);
static tPatternNode* genericPatternSelector(const tMatchedPatternList* matchList, const
    uint8_t* payload);
static void* mlmpMatchPatternCustom(tMlmpTree* root, tMlmpPattern* inputPatternList,
    tPatternNode* (*callback)(const tMatchedPatternList*, const uint8_t*));
static int patternMatcherCallback(void* id, void* unused_tree, int match_end_pos, void* data,
    void* unused_neg);

static uint32_t gPatternId = 1;

tMlmpTree* mlmpCreate()
{
    tMlmpTree* root = (tMlmpTree*)snort_calloc(sizeof(tMlmpTree));
    root->level = 0;
    return root;
}

/*last pattern should be nullptr */
int mlmpAddPattern(tMlmpTree* root, const tMlmpPattern* inputPatternList, void* metaData)
{
    return addPatternRecursively(root, inputPatternList, metaData, 0);
}

int mlmpProcessPatterns(tMlmpTree* root)
{
    int rvalue;

    rvalue = createTreesRecusively(root);
    if (rvalue)
        destroyTreesRecursively(root);
    return rvalue;
}

void* mlmpMatchPatternUrl(tMlmpTree* root, tMlmpPattern* inputPatternList)
{
    return mlmpMatchPatternCustom(root, inputPatternList, urlPatternSelector);
}

void* mlmpMatchPatternGeneric(tMlmpTree* root, tMlmpPattern* inputPatternList)
{
    return mlmpMatchPatternCustom(root, inputPatternList, genericPatternSelector);
}

static inline bool match_is_domain_pattern(const tMatchedPatternList* mp, const uint8_t* payload)
{
    if (!payload)
        return false;

    return mp->patternNode->pattern.level != 0 or
           mp->match_start_pos == 0 or
           payload[mp->match_start_pos-1] == '.';
}

static void* mlmpMatchPatternCustom(tMlmpTree* rootNode, tMlmpPattern* inputPatternList,
    tPatternNode* (*callback)(const tMatchedPatternList*, const uint8_t*))
{
    tMatchedPatternList* mp = nullptr;
    void* data = nullptr;
    void* tmpData = nullptr;
    tPatternPrimaryNode* primaryNode;
    tMlmpPattern* pattern = inputPatternList;

    if (!rootNode || !pattern || !pattern->pattern)
        return nullptr;

    rootNode->patternTree->find_all((const char*)pattern->pattern, pattern->patternSize,
        patternMatcherCallback, false, (void*)&mp);

    primaryNode = (tPatternPrimaryNode*)callback(mp, pattern->pattern);

    while (mp)
    {
        tMatchedPatternList* tmpMp = mp;
        mp = mp->next;
        snort_free(tmpMp);
    }

    if (primaryNode)
    {
        data = primaryNode->patternNode.userData;
        tmpData = mlmpMatchPatternCustom(primaryNode->nextLevelMatcher, ++inputPatternList,
            callback);
        if (tmpData)
            data = tmpData;
    }

    return data;
}

void mlmpDestroy(tMlmpTree* root)
{
    destroyTreesRecursively(root);
}


/**tMlmpPattern comparator: compares patterns based on pattern, patternSize. This will
 * result in alphabetical order. Notice that patternId is ignored here.
 */
static int compareMlmpPatterns(const void* p1, const void* p2)
{
    const tMlmpPattern* pat1 = (const tMlmpPattern*)p1;
    const tMlmpPattern* pat2 = (const tMlmpPattern*)p2;
    int rValue;
    size_t minSize;

    /*first compare patterns by the smaller pattern size, if same then size wins */
    minSize = (pat1->patternSize > pat2->patternSize) ? pat2->patternSize : pat1->patternSize;

    rValue = memcmp(pat1->pattern, pat2->pattern, minSize);
    if (rValue)
        return rValue;

    return ((int)pat1->patternSize - (int)pat2->patternSize);
}

/*pattern trees are not freed on error because in case of error, caller should call
   detroyTreesRecursively. */
static int createTreesRecusively(tMlmpTree* rootNode)
{
    snort::SearchTool* patternMatcher;
    tPatternPrimaryNode* primaryPatternNode;
    tPatternNode* ddPatternNode;

    /* set up the MPSE for url patterns */
    patternMatcher = rootNode->patternTree = new snort::SearchTool("ac_full", true);

    for (primaryPatternNode = rootNode->patternList;
        primaryPatternNode;
        primaryPatternNode = primaryPatternNode->nextPrimaryNode)
    {
        /*recursion into next lower level */
        if (primaryPatternNode->nextLevelMatcher)
        {
            if (createTreesRecusively(primaryPatternNode->nextLevelMatcher))
                return -1;
        }

        for (ddPatternNode = &primaryPatternNode->patternNode;
            ddPatternNode;
            ddPatternNode = ddPatternNode->nextPattern)
        {
            patternMatcher->add(ddPatternNode->pattern.pattern,
                ddPatternNode->pattern.patternSize, ddPatternNode, true);
        }
    }

    patternMatcher->prep();

    return 0;
}

static void destroyTreesRecursively(tMlmpTree* rootNode)
{
    tPatternPrimaryNode* primaryPatternNode;
    uint32_t partNum;

    if (!rootNode)
        return;

    while ((primaryPatternNode = rootNode->patternList))
    {
        /*recursion into next lower level */
        destroyTreesRecursively(primaryPatternNode->nextLevelMatcher);
        rootNode->patternList = primaryPatternNode->nextPrimaryNode;

        for (partNum = 2;
            partNum <= primaryPatternNode->patternNode.partTotal;
            partNum++)
        {
            tPatternNode* patternNode = primaryPatternNode->patternNode.nextPattern + (partNum -2);
            snort_free((void*)patternNode->pattern.pattern);
        }
        snort_free(primaryPatternNode->patternNode.nextPattern);
        snort_free((void*)primaryPatternNode->patternNode.pattern.pattern);
        snort_free(primaryPatternNode);
    }

    delete rootNode->patternTree;
    snort_free(rootNode);
}

/*compares multipart patterns, and orders then according to <patternId, partNum>.
  Comparing multi-parts alphanumerically does not make sense. */
static int compareMlmpPatternList(const tPatternNode* p1, const tPatternNode* p2)
{
    if (p1->patternId != p2->patternId)
        return (p1->patternId - p2->patternId);

    return (p1->partNum - p2->partNum);
}

static tPatternNode* patternSelector(const tMatchedPatternList* patternMatchList, const
    uint8_t* payload, bool domain)
{
    tPatternNode* bestNode = nullptr;
    tPatternNode* currentPrimaryNode = nullptr;
    const tMatchedPatternList* tmpList;
    uint32_t partNum, patternId, patternSize, maxPatternSize;

    /*partTotal = 0; */
    partNum = 0;
    patternId = 0;
    patternSize = maxPatternSize = 0;

    for (tmpList = patternMatchList;
        tmpList;
        tmpList = tmpList->next)
    {
        if (tmpList->patternNode->patternId != patternId)
        {
            /*first pattern */

            /*skip incomplete pattern */
            if (tmpList->patternNode->partNum != 1)
                continue;

            /*new pattern started */
            patternId = tmpList->patternNode->patternId;
            currentPrimaryNode = tmpList->patternNode;
            partNum = 0;
            patternSize = 0;
        }

        if (tmpList->patternNode->partNum == (partNum+1))
        {
            partNum++;
            patternSize += tmpList->patternNode->pattern.patternSize;
        }

        if (tmpList->patternNode->partTotal != partNum)
            continue;

        /*backward compatibility */
        if ((tmpList->patternNode->partTotal == 1)
            && domain && !match_is_domain_pattern(tmpList, payload))
            continue;

        /*last pattern part is seen in sequence */
        if (patternSize >= maxPatternSize)
        {
            maxPatternSize = patternSize;
            bestNode = currentPrimaryNode;
        }
    }

    return bestNode;
}

static tPatternNode* urlPatternSelector(const tMatchedPatternList* patternMatchList, const
    uint8_t* payload)
{
    return patternSelector (patternMatchList, payload, true);
}

static tPatternNode* genericPatternSelector(const tMatchedPatternList* patternMatchList, const
    uint8_t* payload)
{
    return patternSelector (patternMatchList, payload, false);
}

static int patternMatcherCallback(void* id, void*, int match_end_pos, void* data, void*)
{
    tPatternNode* target = (tPatternNode*)id;
    tMatchedPatternList** matchList = (tMatchedPatternList**)data;
    tMatchedPatternList* prevNode;
    tMatchedPatternList* tmpList;
    tMatchedPatternList* newNode;

    /*sort matches by patternId, and then by partId or pattern// */

    for (prevNode = nullptr, tmpList = *matchList;
        tmpList;
        prevNode = tmpList, tmpList = tmpList->next)
    {
        int cmp = compareMlmpPatternList (target, tmpList->patternNode);
        if (cmp > 0 )
            continue;
        if (cmp == 0)
            return 0;
        break;
    }

    newNode = (tMatchedPatternList*)snort_calloc(sizeof(tMatchedPatternList));
    newNode->match_start_pos = match_end_pos - target->pattern.patternSize;
    newNode->patternNode = target;

    if (prevNode == nullptr)
    {
        /*first node */
        newNode->next = *matchList;
        *matchList = newNode;
    }
    else
    {
        newNode->next = prevNode->next;
        prevNode->next = newNode;
    }

    return 0;
}

/*find a match and insertion point if no match is found. Insertion point nullptr means */
static tPatternPrimaryNode* findMatchPattern(tMlmpTree* rootNode, const
    tMlmpPattern* inputPatternList, uint32_t partTotal,
    tPatternPrimaryNode** prevPrimaryPatternNode)
{
    tPatternPrimaryNode* primaryPatternNode;
    tPatternNode* ddPatternNode;
    uint32_t partNum;
    int retVal;

    *prevPrimaryPatternNode = nullptr;

    for (primaryPatternNode = rootNode->patternList;
        primaryPatternNode;
        *prevPrimaryPatternNode = primaryPatternNode, primaryPatternNode =
        primaryPatternNode->nextPrimaryNode
        )
    {
        if (primaryPatternNode->patternNode.partTotal != partTotal)
        {
            continue;
        }

        partNum = 1;
        for (ddPatternNode = &primaryPatternNode->patternNode;
            ddPatternNode;
            ddPatternNode = ddPatternNode->nextPattern)
        {
            retVal = compareMlmpPatterns(inputPatternList+(partNum-1), &ddPatternNode->pattern);
            if (retVal == 0)
            {
                /*all nodes matched */
                if (partNum == ddPatternNode->partTotal)
                    return primaryPatternNode;
                else
                    continue;
            }
            else if (retVal < 0)
            {
                return nullptr;
            }
            break;
        }
        /**prevPrimaryPatternNode = primaryPatternNode; */
    }
    return nullptr;
}

/**
 * @Note
 * a. Patterns in each patternList must be unique. Multipart patterns should be unique i.e. no two multi-part patterns
 * should have same ordered sub-parts.
 * b. Patterns are add in alphabetical ordering of primary nodes.
 */
static int addPatternRecursively(tMlmpTree* rootNode, const tMlmpPattern* inputPatternList,
    void* metaData, uint32_t level)
{
    tPatternNode* newNode;
    tPatternPrimaryNode* prevPrimaryPatternNode = nullptr;
    tPatternPrimaryNode* primaryNode = nullptr;
    const tMlmpPattern* patterns = inputPatternList;
    uint32_t partTotal = 0;
    uint32_t i;

    if (!rootNode || !inputPatternList)
        return -1;

    /*make it easier for user to add patterns by calculating partTotal and partNum */
    for ( i = 0, patterns = inputPatternList;
        patterns->pattern && (patterns->level == level);
        patterns = inputPatternList + (++i))
    {
        partTotal++;
    }

    /*see if pattern is present already. Multipart-messages are considered match only if all parts
      match. */
    primaryNode = findMatchPattern(rootNode, inputPatternList, partTotal, &prevPrimaryPatternNode);

    /*pattern not found, insert it in order */
    if (!primaryNode)
    {
        tPatternPrimaryNode* tmpPrimaryNode;
        uint32_t partNum;

        tmpPrimaryNode = (tPatternPrimaryNode*)snort_calloc(sizeof(tPatternPrimaryNode));
        if (partTotal > 1)
            tmpPrimaryNode->patternNode.nextPattern =
                (tPatternNode*)snort_calloc((partTotal - 1) * sizeof(tPatternNode));
        uint32_t patternId = gPatternId++;
        i = 0;
        patterns = inputPatternList + i;

        /*initialize primary Node */
        tmpPrimaryNode->patternNode.pattern.pattern = patterns->pattern;
        tmpPrimaryNode->patternNode.pattern.patternSize = patterns->patternSize;
        tmpPrimaryNode->patternNode.pattern.level = patterns->level;
        tmpPrimaryNode->patternNode.partNum = 1;
        tmpPrimaryNode->patternNode.partTotal = partTotal;
        tmpPrimaryNode->patternNode.patternId = patternId;

        if (prevPrimaryPatternNode)
        {
            tmpPrimaryNode->nextPrimaryNode = prevPrimaryPatternNode->nextPrimaryNode;
            prevPrimaryPatternNode->nextPrimaryNode = tmpPrimaryNode;
        }
        else
        {
            /*insert as first node since either this is the only node, or this is lexically
               smallest. */
            tmpPrimaryNode->nextPrimaryNode = rootNode->patternList;
            rootNode->patternList = tmpPrimaryNode;
        }

        i++;
        patterns = inputPatternList + i;

        /*create list of remaining nodes  */
        for (partNum = 2; partNum <= partTotal; partNum++)
        {
            newNode = tmpPrimaryNode->patternNode.nextPattern + (partNum -2);
            newNode->pattern.pattern = patterns->pattern;
            newNode->pattern.patternSize = patterns->patternSize;
            newNode->pattern.level = patterns->level;
            newNode->partNum = partNum;
            newNode->partTotal = partTotal;
            newNode->patternId = patternId;
            if (partNum < partTotal)
                newNode->nextPattern = newNode+1;
            else
                newNode->nextPattern = nullptr;

            i++;
            patterns = inputPatternList + i;
        }
        primaryNode = tmpPrimaryNode;
    }
    else
    {
        for (i = 0; i < primaryNode->patternNode.partTotal; i++)
            snort_free((void*)(inputPatternList+i)->pattern);
    }

    if (primaryNode)
    {
        /*move down the new node */
        const tMlmpPattern* nextPattern = inputPatternList + partTotal;
        if (!nextPattern || !nextPattern->pattern)
        {
            primaryNode->patternNode.userData = metaData;
        }
        else
        {
            if (!primaryNode->nextLevelMatcher)
            {
                tMlmpTree* tmpRootNode;

                tmpRootNode = (tMlmpTree*)snort_calloc(sizeof(tMlmpTree));
                primaryNode->nextLevelMatcher = tmpRootNode;
                primaryNode->nextLevelMatcher->level = rootNode->level+1;
            }
            addPatternRecursively(primaryNode->nextLevelMatcher, inputPatternList+partTotal,
                metaData, level+1);
        }
    }

    return 0;
}

