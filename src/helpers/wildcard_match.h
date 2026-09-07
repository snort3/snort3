#ifndef WILDCARD_MATCH_H
#define WILDCARD_MATCH_H

#include <string>

inline bool wildcard_match(const char* pattern, const char* str)
{
    if (!pattern || !str)
        return false;

    const char* p = pattern;
    const char* s = str;
    const char* star = nullptr;
    const char* match = nullptr;

    while (*s)
    {
        if (*p == '?' || *p == *s)
        {
            ++p;
            ++s;
        }
        else if (*p == '*')
        {
            star = p++;
            match = s;
        }
        else if (star)
        {
            p = star + 1;
            s = ++match;
        }
        else
        {
            return false;
        }
    }

    while (*p == '*')
        ++p;

    return *p == '\0';
}

#endif