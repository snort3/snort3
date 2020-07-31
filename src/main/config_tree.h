//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// config_tree.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef CONFIG_TREE_H
#define CONFIG_TREE_H

#include <list>

#include "framework/value.h"

class BaseConfigNode;

using ChildrenNodes = std::list<BaseConfigNode*>;

class ConfigTextFormat
{
public:
    static void print(const BaseConfigNode* parent, const std::string& config_name);
};

class BaseConfigNode
{
public:
    BaseConfigNode(BaseConfigNode* parent);
    virtual ~BaseConfigNode() = default;

    virtual std::string get_name() const = 0;
    virtual snort::Parameter::Type get_type() const = 0;
    virtual BaseConfigNode* get_node(const std::string& name) = 0;
    virtual std::string data() const { return ""; }
    virtual void set_value(const snort::Value&) {}

    const ChildrenNodes& get_children() const
    { return children; }

    BaseConfigNode* get_parent_node() const
    { return parent; }

    void add_child_node(BaseConfigNode* node);

    static void clear_nodes(BaseConfigNode* root);

protected:
    ChildrenNodes children;
    BaseConfigNode* parent = nullptr;
};

class TreeConfigNode : public BaseConfigNode
{
public:
    TreeConfigNode(BaseConfigNode* parent, const std::string& node_name,
        const snort::Parameter::Type node_type);

private:
    virtual std::string get_name() const override
    { return name; }

    virtual snort::Parameter::Type get_type() const override
    { return type; }

    virtual BaseConfigNode* get_node(const std::string& name) override;

private:
    std::string name;
    snort::Parameter::Type type = snort::Parameter::PT_MAX;
};

class ValueConfigNode : public BaseConfigNode
{
public:
    ValueConfigNode(BaseConfigNode* parent, const snort::Value& value);

private:
    virtual std::string get_name() const override
    { return value.get_name(); }

    virtual snort::Parameter::Type get_type() const override
    { return value.get_param_type(); }

    virtual std::string data() const override
    { return value.get_origin_string(); }

    virtual void set_value(const snort::Value& v) override
    { value = v; }

    virtual BaseConfigNode* get_node(const std::string& name) override;

private:
    snort::Value value;
};

#endif // CONFIG_TREE_H

