//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// config_data.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef CONFIG_DATA_H
#define CONFIG_DATA_H

#include <list>

#include "framework/value.h"

class BaseConfigNode;

using ConfigTrees = std::list<BaseConfigNode*>;

class BaseConfigNode
{
public:
    BaseConfigNode(BaseConfigNode* parent);
    virtual ~BaseConfigNode() = default;

    virtual std::string get_name() const = 0;
    virtual snort::Parameter::Type get_type() const = 0;
    virtual BaseConfigNode* get_node(const std::string& name) = 0;
    virtual void set_value(const snort::Value&) {}
    virtual const snort::Value* get_value() const { return nullptr; }

    const ConfigTrees& get_children() const
    { return children; }

    BaseConfigNode* get_parent_node() const
    { return parent; }

    void add_child_node(BaseConfigNode* node);

    static void clear_nodes(BaseConfigNode* root);
    static void sort_nodes(BaseConfigNode* node);

protected:
    ConfigTrees children;
    BaseConfigNode* parent = nullptr;
};

class TreeConfigNode : public BaseConfigNode
{
public:
    TreeConfigNode(BaseConfigNode* parent, const std::string& node_name,
        const snort::Parameter::Type node_type);

private:
    std::string get_name() const override
    { return name; }

    snort::Parameter::Type get_type() const override
    { return type; }

    BaseConfigNode* get_node(const std::string& name) override;

private:
    std::string name;
    snort::Parameter::Type type = snort::Parameter::PT_MAX;
};

class ValueConfigNode : public BaseConfigNode
{
public:
    ValueConfigNode(BaseConfigNode* parent, const snort::Value& value,
        const std::string& name = "");

private:
    std::string get_name() const override
    { return !custom_name.empty() ? custom_name : value.get_name(); }

    snort::Parameter::Type get_type() const override
    { return value.get_param_type(); }

    const snort::Value* get_value() const override
    { return &value; }

    void set_value(const snort::Value& v) override;
    BaseConfigNode* get_node(const std::string& name) override;

private:
    snort::Value value;
    bool multi_value = false;
    std::string custom_name;
};

class ConfigData
{
public:
    ConfigData(const char* file_name);

    void add_config_tree(BaseConfigNode* root)
    { config_trees.push_back(root); }

    void sort();
    void clear();

public:
    std::string file_name;
    ConfigTrees config_trees;
};

#endif // CONFIG_DATA_H

