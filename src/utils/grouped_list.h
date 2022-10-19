//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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

// grouped_list.h author Cisco

#ifndef GROUPED_LIST_H
#define GROUPED_LIST_H

// The class below represents a group (double-linked list) of elements,
// where each element belongs to a sub-group.
// Sub-groups never intersect,
// but a sub-group of elements can be deleted altogether from the main group.

#include <assert.h>

namespace snort
{

template <class T>
class GroupedList
{
public:
    GroupedList();
    GroupedList(GroupedList& cont, GroupedList*& group, const T& value);
    GroupedList(GroupedList& cont, GroupedList*& group, T&& value);
    template <class... Args>
    GroupedList(GroupedList& cont, GroupedList*& group, Args&&... args);
    ~GroupedList();

    inline T& operator *();
    inline GroupedList* get_next() const;
    inline void leave_group();
    inline static unsigned erase_group(GroupedList*& group);

private:
    inline void init();
    inline void leave();
    inline void erase_all();

    GroupedList* prev;       // previous element in a container (list 1)
    GroupedList* next;       // next element in a container (list 1)
    GroupedList* mate;       // next element in a group (list 2)
    GroupedList** grp;       // pointer to this element, a group holder (list 2)
    T value;                 // value of element
    const bool holder;       // if the element is a container holder
};

template <typename T>
GroupedList<T>::GroupedList()
    : prev(this), next(this), mate(nullptr), grp(nullptr), holder(true)
{ }

template <typename T>
GroupedList<T>::GroupedList(GroupedList& cont, GroupedList*& group, const T& v)
    : prev(cont.prev), next(&cont), mate(group), grp(&group), value(v), holder(false)
{
    init();
    group = this;
}

template <typename T>
GroupedList<T>::GroupedList(GroupedList& cont, GroupedList*& group, T&& v)
    : prev(cont.prev), next(&cont), mate(group), grp(&group),value(v), holder(false)
{
    init();
    group = this;
}

template <typename T> template <class... Args>
GroupedList<T>::GroupedList(GroupedList& cont, GroupedList*& group, Args&&... args)
    : prev(cont.prev), next(&cont), mate(group), grp(&group),value{std::forward<Args>(args)...}, holder(false)
{
    init();
    group = this;
}

template <typename T>
GroupedList<T>::~GroupedList()
{
    if (holder)
        erase_all();
    else
        leave();
}

template <typename T>
T& GroupedList<T>::operator *()
{
    return value;
}

template <typename T>
GroupedList<T>* GroupedList<T>::get_next() const
{
    return next;
}

template <typename T>
inline void GroupedList<T>::leave_group()
{
    if (grp)
        *grp = *grp == this ? mate : nullptr;

    if (mate)
        mate->grp = grp;

    grp = nullptr;
    mate = nullptr;

    assert(!holder);
}

template <typename T>
inline void GroupedList<T>::init()
{
    assert(prev);
    assert(next);
    assert(next->holder);
    assert(!mate or !mate->holder);

    prev->next = this;
    next->prev = this;

    if (mate)
        mate->grp = &mate;
}

template <typename T>
void GroupedList<T>::leave()
{
    assert(!prev or prev->next == this);
    assert(!next or next->prev == this);

    if (prev)
        prev->next = next;

    if (next)
        next->prev = prev;
}

template <typename T>
void GroupedList<T>::erase_all()
{
    auto it = next;

    while (it != this)
    {
        auto el = it;
        it = it->next;

        assert(!el->holder);
        delete el;
    }
}

template <typename T>
unsigned GroupedList<T>::erase_group(GroupedList<T>*& group)
{
    unsigned cnt = 0;
    auto it = group;
    group = nullptr;

    while (it)
    {
        auto el = it;
        it = it->mate;
        ++cnt;

        assert(!el->holder);
        delete el;
    }

    return cnt;
}

}

#endif
